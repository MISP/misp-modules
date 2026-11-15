"""Generate native osquery 5.24.1 logs using a disposable synthetic query pack.

Run from the repository with OSQUERYD=/path/to/osqueryd python reproduce.py.
Only synthetic SQL, a temporary indicator file and isolated local daemon state
are used. No endpoint service, real hunting data or network logger is contacted.
"""

import json
import os
import subprocess
import time
from pathlib import Path

from misp_modules.lib.osquery import build


def read_logs(directory, name):
    path = directory / name
    return path.read_text() if path.exists() else ""


def main():
    binary = Path(os.environ["OSQUERYD"]).resolve()
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    assert version == "osqueryd version 5.24.1", version
    root = Path(os.environ.get("OSQUERY_FIXTURE_WORK", "/workspace/work/osquery-native")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).parent
    indicator = root / "synthetic-indicator.txt"
    event = {
        "uuid": "8aeea4c1-ce72-4ecb-8115-4c1b30f99ef6",
        "Attribute": [
            {
                "uuid": "3f6d4ee0-f1f6-439d-adb3-26b9b257f50e",
                "type": "filename",
                "value": str(indicator),
                "to_ids": True,
            }
        ],
    }
    pack, _, sources = build([event], {"interval": 1})
    query = next(iter(pack["queries"]))
    pack["queries"][query]["removed"] = True  # Exercise removal logging; exporter defaults remain unchanged.
    pack["queries"]["snapshot_rows_with_underscores"] = {
        "query": "SELECT 'synthetic' AS label, 42 AS value;",
        "interval": 1,
        "snapshot": True,
    }
    pack["queries"]["empty_snapshot"] = {
        "query": "SELECT 'no rows' AS label WHERE 0;",
        "interval": 1,
        "snapshot": True,
    }
    pack_name = "misp_fixture_pack_with_underscores"
    for profile, event_type, snapshot_events in [
        ("event", True, False),
        ("batch", False, False),
        ("snapshot-event", True, True),
    ]:
        directory = root / profile
        directory.mkdir(exist_ok=True)
        indicator.write_text("synthetic osquery indicator\n")
        config = directory / "osquery.conf"
        config.write_text(json.dumps({"packs": {pack_name: pack}}))
        for name in ("osqueryd.results.log", "osqueryd.snapshots.log"):
            (directory / name).unlink(missing_ok=True)
        command = [
            str(binary),
            "--disable_watchdog",
            "--disable_events",
            "--disable_extensions",
            "--ephemeral",
            "--logger_plugin=filesystem",
            "--host_identifier=specified",
            "--specified_identifier=fixture-host",
            "--schedule_splay_percent=0",
            "--schedule_epoch=314159265",
            "--logger_numerics=true",
            "--logger_stderr=false",
            "--logger_min_status=2",
            f"--config_path={config}",
            f"--database_path={directory / 'db'}",
            f"--pidfile={directory / 'pid'}",
            f"--logger_path={directory}",
            "--logger_event_type=" + str(event_type).lower(),
            "--logger_snapshot_event_type=" + str(snapshot_events).lower(),
        ]
        with (directory / "daemon.log").open("w") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                deleted = False
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError((directory / "daemon.log").read_text())
                    text = read_logs(directory, "osqueryd.results.log")
                    records = [json.loads(line) for line in text.splitlines() if line]
                    added = any(r.get("action") == "added" or r.get("diffResults", {}).get("added") for r in records)
                    removed = any(
                        r.get("action") == "removed" or r.get("diffResults", {}).get("removed") for r in records
                    )
                    snapshots = read_logs(directory, "osqueryd.snapshots.log")
                    if added and not deleted:
                        indicator.unlink()
                        deleted = True
                    if removed and snapshots:
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError(
                        "Timed out waiting for native fixture logs: " + (directory / "daemon.log").read_text()
                    )
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        (fixture / (profile + ".jsonl")).write_text(read_logs(directory, "osqueryd.results.log"))
        (fixture / (profile + "-snapshots.jsonl")).write_text(read_logs(directory, "osqueryd.snapshots.log"))
    (fixture / "sources.json").write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
    (fixture / "manifest.json").write_text(
        json.dumps({"version": "5.24.1", "pack_name": pack_name, "query_name": query, "event": event}, indent=2) + "\n"
    )
    shell = root / "osqueryi"
    if not shell.exists():
        shell.symlink_to(binary)
    output = subprocess.check_output(
        [
            str(shell),
            "--disable_extensions",
            "--disable_events",
            "--disable_logging",
            "--json",
            "SELECT 'synthetic' AS label, 42 AS value;",
        ],
        text=True,
    )
    (fixture / "adhoc.json").write_text(output)


if __name__ == "__main__":
    main()
