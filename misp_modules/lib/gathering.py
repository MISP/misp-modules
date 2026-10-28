"""Shared, versioned MISP feed contract for gathering modules.

The envelope transports ordinary manifest.json and <uuid>.json contents in one
bounded response. No consumer-specific import state is kept by this service.
"""

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from uuid import UUID, uuid5

CONTRACT_VERSION = 1
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 100
NAMESPACE = UUID("60ad67e2-2475-5ae1-bc8d-6b706ff51e84")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def stable_uuid(parent, *parts):
    return str(uuid5(UUID(str(parent)), canonical_json(parts)))


class RevisionStore:
    """Keep monotonically increasing event revisions across workers and restarts.

    Set MISP_MODULES_GATHERING_STATE_DIR to durable service-owned storage in
    production. SQLite serializes writers, including concurrent module requests.
    """

    def __init__(self, directory=None):
        directory = directory or os.environ.get("MISP_MODULES_GATHERING_STATE_DIR")
        if directory is None:
            directory = Path(tempfile.gettempdir()) / f"misp-modules-gathering-{os.getuid()}"
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "revisions.sqlite3"

    def revision(self, event_uuid, digest, source_timestamp):
        with closing(sqlite3.connect(self.path, timeout=20)) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS revisions (uuid TEXT PRIMARY KEY, digest TEXT NOT NULL, timestamp INTEGER"
                " NOT NULL)"
            )
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT digest, timestamp FROM revisions WHERE uuid = ?", (event_uuid,)
            ).fetchone()
            if previous and previous[0] == digest:
                return previous[1]
            timestamp = int(source_timestamp)
            if previous:
                timestamp = max(timestamp, previous[1] + 1, int(time.time()))
            connection.execute("INSERT OR REPLACE INTO revisions VALUES (?, ?, ?)", (event_uuid, digest, timestamp))
            return timestamp


class FeedBuilder:
    """Build standard MISP feed files with a stable content-based revision."""

    def __init__(self, revisions=None):
        self.revisions = revisions or RevisionStore()
        self.events = {}

    def add(self, event, source_timestamp):
        event = copy.deepcopy(event)
        event_uuid = event["uuid"]
        UUID(event_uuid)
        if event_uuid in self.events:
            raise ValueError("Duplicate event UUID in gathering result")
        if len(self.events) >= MAX_EVENTS:
            raise ValueError("Generated feed exceeds 100 events; select a smaller date range")
        digest = hashlib.sha256(canonical_json(event).encode()).hexdigest()
        timestamp = self.revisions.revision(event_uuid, digest, source_timestamp)
        event["timestamp"] = str(timestamp)
        event["publish_timestamp"] = str(timestamp)
        for attribute in event.get("Attribute", []):
            attribute["timestamp"] = str(timestamp)
        for obj in event.get("Object", []):
            obj["timestamp"] = str(timestamp)
            for attribute in obj.get("Attribute", []):
                attribute["timestamp"] = str(timestamp)
        self.events[event_uuid] = {"Event": event}

    def build(self):
        manifest = {}
        for event_uuid, wrapped in sorted(self.events.items()):
            event = wrapped["Event"]
            manifest[event_uuid] = {
                key: event[key]
                for key in ("info", "date", "timestamp", "publish_timestamp", "Orgc", "Tag")
                if key in event
            }
        result = {
            "gathering_version": CONTRACT_VERSION,
            "source_format": "misp",
            "manifest": manifest,
            "events": dict(sorted(self.events.items())),
        }
        if len(canonical_json(result).encode()) > MAX_BUNDLE_BYTES:
            raise ValueError("Generated feed exceeds 32 MiB; select a smaller date range")
        return result


def write_feed(bundle, directory):
    """Materialize a bundle as a conventional feed in a new directory.

    Refuse existing destinations so consumers never see a partly replaced feed.
    The caller can publish the completed directory with an atomic rename.
    """
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for event_uuid, event in bundle["events"].items():
        UUID(event_uuid)
        (directory / f"{event_uuid}.json").write_text(canonical_json(event), encoding="utf-8")
    (directory / "manifest.json").write_text(canonical_json(bundle["manifest"]), encoding="utf-8")
