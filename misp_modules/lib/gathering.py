"""Shared, versioned MISP feed contract for gathering modules.

Jobs write ordinary manifest.json and <uuid>.json files and return a ZIP artifact.
No consumer-specific import state is kept by this service.
"""

import hashlib
import json
import logging
import os
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from uuid import UUID, uuid5

import psutil

from misp_modules.http_debug import module_context

CONTRACT_VERSION = 2
NAMESPACE = UUID("60ad67e2-2475-5ae1-bc8d-6b706ff51e84")
_CHILD_COLLECTIONS = {"Event": ("Attribute", "Object"), "Object": ("Attribute",), "Attribute": ()}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def stable_uuid(parent, *parts):
    """Derive a UUIDv5 from a fixed namespace and ordered, JSON-serializable source keys."""
    return str(uuid5(UUID(str(parent)), canonical_json(parts)))


def origin_tags(module, source):
    """Event-local provenance using the misp-gathering taxonomy.

    Use the module identifier and upstream provider's domain, not a retrieval URL
    or time. MISP imports Tag.local as the locality of the event/tag association.
    """
    return [
        {"name": f'misp-gathering:module="{module}"', "local": True},
        {"name": f'misp-gathering:source="{source}"', "local": True},
    ]


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


@dataclass
class _FeedItem:
    data: dict
    digest: str
    parent: str | None


def _prepare_item(kind, source, parent, items):
    """Index the MISP hierarchy by UUID and hash only import-relevant content."""
    try:
        identifier = UUID(source["uuid"])
        if identifier.version != 5:
            raise ValueError
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"Gathering {kind} requires a UUIDv5") from exc

    uuid = str(identifier)
    data = dict(source, uuid=uuid)
    data.pop("timestamp", None)
    if kind == "Event":
        data.pop("publish_timestamp", None)
    if "Tag" in data:
        data["Tag"] = sorted(data["Tag"], key=canonical_json)
    content = data.copy()
    for collection in _CHILD_COLLECTIONS[kind]:
        if collection not in data:
            continue
        children = {}
        for child in data[collection]:
            item = _prepare_item(collection, child, uuid, items)
            children[item.data["uuid"]] = item
        data[collection] = [children[key].data for key in sorted(children)]
        content[collection] = {key: item.digest for key, item in children.items()}

    digest = _digest([kind, content])
    if uuid in items:
        previous = items[uuid]
        if previous.parent != parent or previous.digest != digest:
            raise ValueError(f"Conflicting gathering {kind} UUID {uuid}")
        return previous
    items[uuid] = _FeedItem(data, digest, parent)
    return items[uuid]


class RevisionStore:
    """Opt-in revision history for callers that need to publish same-time corrections.

    Callers selecting this mode need a common database to agree on revisions.
    SQLite serializes concurrent writers.
    """

    def __init__(self, directory=None):
        directory = directory or os.environ.get("MISP_MODULES_GATHERING_STATE_DIR")
        if directory is None:
            directory = Path(tempfile.gettempdir()) / f"misp-modules-gathering-{os.getuid()}"
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "revisions.sqlite3"

    def stamp(self, source, event, items, source_timestamp):
        event_uuid = event.data["uuid"]
        with closing(sqlite3.connect(self.path, timeout=20)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS revisions (uuid TEXT PRIMARY KEY, digest TEXT NOT NULL, timestamp INTEGER"
                " NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS child_revisions (uuid TEXT PRIMARY KEY, parent TEXT NOT NULL,"
                " digest TEXT NOT NULL, timestamp INTEGER NOT NULL)"
            )
            previous = connection.execute(
                "SELECT digest, timestamp FROM revisions WHERE uuid = ?", (event_uuid,)
            ).fetchone()
            digest = "v2:" + event.digest
            timestamp = int(source_timestamp)
            if previous:
                old_digest, old_timestamp = previous
                # Older installations hashed the raw event and stamped every child with its revision.
                if old_digest == digest or (not old_digest.startswith("v2:") and old_digest == _digest(source)):
                    timestamp = old_timestamp
                else:
                    timestamp = max(timestamp, old_timestamp + 1, int(time.time()))
            if not previous or previous[0] != digest:
                connection.execute("INSERT OR REPLACE INTO revisions VALUES (?, ?, ?)", (event_uuid, digest, timestamp))
            event.data["timestamp"] = event.data["publish_timestamp"] = str(timestamp)

            for uuid, item in items.items():
                if item is event:
                    continue
                row = connection.execute(
                    "SELECT parent, digest, timestamp FROM child_revisions WHERE uuid = ?", (uuid,)
                ).fetchone()
                if row and row[0] != item.parent:
                    raise ValueError(f"Gathering UUID {uuid} belongs to another parent")
                if row and row[1] == item.digest:
                    item.data["timestamp"] = str(row[2])
                else:
                    connection.execute(
                        "INSERT OR REPLACE INTO child_revisions VALUES (?, ?, ?, ?)",
                        (uuid, item.parent, item.digest, timestamp),
                    )
                    item.data["timestamp"] = str(timestamp)


class GenerationCancelled(ValueError):
    pass


class FeedBuilder:
    """Write one event at a time; keep the manifest index in SQLite, not RAM."""

    def __init__(self, directory, revisions=None, check_cancel=None):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.revisions = revisions
        self.check_cancel = check_cancel or (lambda: None)
        self.index = self.directory.parent / "manifest.sqlite3"
        self.max_event_bytes = int(os.environ.get("MISP_MODULES_GATHERING_MAX_EVENT_BYTES", 256 * 1024 * 1024))
        self.max_bytes = int(os.environ.get("MISP_MODULES_GATHERING_MAX_BYTES", 10 * 1024**3))
        self.bytes_written = 0
        self.event_count = 0
        with closing(sqlite3.connect(self.index)) as connection:
            connection.execute(
                "CREATE TABLE manifest (uuid TEXT PRIMARY KEY, metadata TEXT NOT NULL, digest TEXT NOT NULL)"
            )
            connection.execute("CREATE TABLE item_uuids (uuid TEXT PRIMARY KEY) WITHOUT ROWID")
            connection.commit()

    def add(self, event, source_timestamp):
        """Use the upstream revision time unless the caller explicitly supplies a RevisionStore."""
        self.check_cancel()
        items = {}
        root = _prepare_item("Event", event, None, items)
        event_uuid = root.data["uuid"]
        source_timestamp = int(source_timestamp)
        feed_digest = _digest([root.digest, source_timestamp])
        with closing(sqlite3.connect(self.index)) as connection, connection:
            existing = connection.execute("SELECT digest FROM manifest WHERE uuid = ?", (event_uuid,)).fetchone()
            if existing:
                if existing[0] == feed_digest:
                    return
                raise ValueError(f"Conflicting gathering Event UUID {event_uuid}")

            # A MISP UUID can belong to only one event. Check ownership within this job.
            try:
                connection.executemany("INSERT INTO item_uuids VALUES (?)", ((uuid,) for uuid in items))
            except sqlite3.IntegrityError as exc:
                raise ValueError("Gathering UUID reused across events in the same feed") from exc

            if self.revisions is None:
                timestamp = str(source_timestamp)
                for item in items.values():
                    item.data["timestamp"] = timestamp
                root.data["publish_timestamp"] = timestamp
            else:
                self.revisions.stamp(event, root, items, source_timestamp)
            event = root.data
            metadata = {
                key: event[key]
                for key in ("info", "date", "timestamp", "publish_timestamp", "Orgc", "Tag")
                if key in event
            }
            path = self.directory / f"{event_uuid}.json"
            with path.open("x", encoding="utf-8") as output:
                size = 0
                for chunk in json.JSONEncoder(
                    sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
                ).iterencode({"Event": event}):
                    size += len(chunk.encode())
                    if size > self.max_event_bytes or self.bytes_written + size > self.max_bytes:
                        raise ValueError("Gathering event or disk budget exceeded")
                    output.write(chunk)
            connection.execute(
                "INSERT INTO manifest VALUES (?, ?, ?)", (event_uuid, canonical_json(metadata), feed_digest)
            )
        self.bytes_written += size
        self.event_count += 1

    def archive(self, destination):
        self.check_cancel()
        with (self.directory / "manifest.json").open("w", encoding="utf-8") as output:
            output.write("{")
            with closing(sqlite3.connect(self.index)) as connection:
                separator = ""
                for event_uuid, metadata in connection.execute("SELECT uuid, metadata FROM manifest ORDER BY uuid"):
                    self.check_cancel()
                    output.write(separator + canonical_json(event_uuid) + ":" + metadata)
                    separator = ","
            output.write("}")
        # ZIP central-directory records contain filenames/sizes, never event bodies.
        with (
            zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive,
            closing(sqlite3.connect(self.index)) as connection,
        ):
            event_names = (uuid + ".json" for (uuid,) in connection.execute("SELECT uuid FROM manifest ORDER BY uuid"))
            for name in chain(("manifest.json",), event_names):
                self.check_cancel()
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                with (self.directory / name).open("rb") as source, archive.open(info, "w", force_zip64=True) as output:
                    while chunk := source.read(64 * 1024):
                        self.check_cancel()
                        output.write(chunk)
        digest = hashlib.sha256()
        with open(destination, "rb") as source:
            while chunk := source.read(64 * 1024):
                self.check_cancel()
                digest.update(chunk)
        return {
            "event_count": self.event_count,
            "archive_size": Path(destination).stat().st_size,
            "sha256": digest.hexdigest(),
        }


class GatheringJobs:
    """Disk-backed artifacts with bounded background concurrency and capability IDs.

    Ready artifacts survive service restarts. Interrupted generation is reported
    as failed rather than publishing an incomplete feed. No credentials are saved.
    """

    def __init__(self, directory=None, workers=None):
        root = directory or os.environ.get("MISP_MODULES_GATHERING_STATE_DIR")
        if root is None:
            root = Path(tempfile.gettempdir()) / f"misp-modules-gathering-{os.getuid()}"
        self.directory = Path(root) / "jobs"
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        workers = workers or int(os.environ.get("MISP_MODULES_GATHERING_WORKERS", 2))
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="gathering")
        self.slots = threading.BoundedSemaphore(workers + int(os.environ.get("MISP_MODULES_GATHERING_QUEUE", 8)))
        self.timeout = int(os.environ.get("MISP_MODULES_GATHERING_TIMEOUT", 86400))
        self.retention = int(os.environ.get("MISP_MODULES_GATHERING_RETENTION", 86400))

    def path(self, identifier):
        if (
            not isinstance(identifier, str)
            or len(identifier) != 64
            or any(c not in "0123456789abcdef" for c in identifier)
        ):
            raise FileNotFoundError("Unknown gathering job")
        return self.directory / identifier

    @staticmethod
    def _write(directory, metadata):
        temporary = directory / ("status-" + secrets.token_hex(8))
        temporary.write_text(canonical_json(metadata), encoding="utf-8")
        temporary.replace(directory / "status.json")

    def submit(self, module, parameters, config, producer):
        if not self.slots.acquire(blocking=False):
            raise ValueError("Gathering queue is full; retry later")
        identifier = secrets.token_hex(32)
        directory = self.path(identifier)
        try:
            directory.mkdir(mode=0o700)
            metadata = {
                "gathering_version": CONTRACT_VERSION,
                "source_format": "misp",
                "job_id": identifier,
                "module": module,
                "status": "queued",
                "created_at": int(time.time()),
                "owner_pid": os.getpid(),
                "owner_started": psutil.Process().create_time(),
            }
            self._write(directory, metadata)
            self.executor.submit(self._run, directory, dict(metadata), parameters, config, producer)
            return self.public(metadata)
        except Exception:
            shutil.rmtree(directory, ignore_errors=True)
            self.slots.release()
            raise

    def _run(self, directory, metadata, parameters, config, producer):
        started = time.monotonic()
        builder = None
        last_progress = started

        def check():
            nonlocal last_progress
            if (directory / "cancel").exists() or time.monotonic() - started > self.timeout:
                raise GenerationCancelled("Gathering generation cancelled or timed out")
            if builder is not None and time.monotonic() - last_progress >= 1:
                metadata.update(event_count=builder.event_count, bytes_written=builder.bytes_written)
                self._write(directory, metadata)
                last_progress = time.monotonic()

        try:
            try:
                check()
                metadata["status"] = "running"
                self._write(directory, metadata)
                builder = FeedBuilder(directory / "feed", check_cancel=check)
                with module_context(metadata["module"]):
                    producer(parameters, builder=builder, config=config)
                check()
                metadata.update(builder.archive(directory / "feed.zip.partial"))
                (directory / "feed.zip.partial").replace(directory / "feed.zip")
            finally:
                shutil.rmtree(directory / "feed", ignore_errors=True)
                (directory / "manifest.sqlite3").unlink(missing_ok=True)

            metadata.update(status="ready", expires_at=int(time.time()) + self.retention)
            self._write(directory, metadata)
        except Exception:
            logging.getLogger("misp-modules").exception("Gathering job %s failed", directory.name)
            (directory / "feed.zip.partial").unlink(missing_ok=True)
            (directory / "feed.zip").unlink(missing_ok=True)
            metadata.update(
                status="failed",
                error="Generation failed or was interrupted; see the module service logs.",
                expires_at=int(time.time()) + self.retention,
            )
            self._write(directory, metadata)
        finally:
            if (directory / "cancel").exists():
                shutil.rmtree(directory, ignore_errors=True)
            self.slots.release()

    @staticmethod
    def public(metadata):
        return {key: value for key, value in metadata.items() if key not in ("owner_pid", "owner_started")}

    def status(self, identifier):
        directory = self.path(identifier)
        metadata = json.loads((directory / "status.json").read_text())
        if metadata.get("expires_at", float("inf")) < time.time():
            self.delete(identifier)
            raise FileNotFoundError("Gathering artifact expired")
        if metadata["status"] in ("queued", "running"):
            try:
                if psutil.Process(metadata["owner_pid"]).create_time() != metadata["owner_started"]:
                    raise psutil.NoSuchProcess(metadata["owner_pid"])
            except psutil.NoSuchProcess:
                metadata.update(
                    status="failed",
                    error="Generation interrupted by a service restart; submit a new job.",
                    expires_at=int(time.time()) + self.retention,
                )
                self._write(directory, metadata)
                shutil.rmtree(directory / "feed", ignore_errors=True)
                (directory / "feed.zip.partial").unlink(missing_ok=True)
        return self.public(metadata)

    def archive_path(self, identifier):
        if self.status(identifier)["status"] != "ready":
            raise ValueError("Gathering archive is not ready")
        return self.path(identifier) / "feed.zip"

    def delete(self, identifier):
        directory = self.path(identifier)
        metadata = json.loads((directory / "status.json").read_text())
        if metadata["status"] in ("queued", "running"):
            (directory / "cancel").touch()
        else:
            shutil.rmtree(directory)

    def reap(self):
        for directory in self.directory.iterdir():
            try:
                self.status(directory.name)
            except (FileNotFoundError, ValueError):
                continue


_jobs = None
_jobs_lock = threading.Lock()


def get_jobs():
    global _jobs
    with _jobs_lock:
        if _jobs is None:
            _jobs = GatheringJobs()
        return _jobs
