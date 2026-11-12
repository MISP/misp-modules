"""Generate real incremental feed responses without retaining an event set in RAM.

Run with --events 5000 --context-kib 64 --parts /tmp/feed-parts.jsonl, then
use MISP's app/Test/benchmark_module_feed_export.php to assemble the parts.
"""

import argparse
import csv
import hashlib
import io
import json
import resource
import secrets
import time
import uuid
import zipfile
from pathlib import Path

from misp_modules.modules.export_mod import misp_feed


def identifier(number):
    return str(uuid.UUID(int=number, version=4))


def verify(path):
    """Check every event identity, lookup hash and ZIP CRC while reading files."""
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert set(archive.namelist()) == {"manifest.json", "hashes.csv", *(key + ".json" for key in manifest)}
        rows = csv.reader(io.TextIOWrapper(archive.open("hashes.csv"), encoding="utf-8"))
        count = 0
        for key in manifest:
            event = json.loads(archive.read(key + ".json"))["Event"]
            assert event["uuid"] == key
            attributes = event.get("Attribute", []) + [a for obj in event.get("Object", []) for a in obj["Attribute"]]
            values = [
                v
                for a in attributes
                for v in (
                    str(a["value"]).split("|")
                    if "|" in a["type"] or a["type"] == "malware-sample"
                    else [str(a["value"])]
                )
            ]
            expected = sorted({hashlib.md5(value.encode()).hexdigest() for value in values})
            for digest in expected:
                assert next(rows) == [digest, key]
                count += 1
        assert next(rows, None) is None
    return {"event_files": len(manifest), "verified_hash_rows": count, "zip_crc": "all valid"}


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--context-kib", type=int, default=64)
    parser.add_argument("--parts", type=Path)
    parser.add_argument("--verify-archive", type=Path)
    args = parser.parse_args()
    if args.verify_archive:
        print(json.dumps(verify(args.verify_archive)))
        return
    if not args.parts:
        parser.error("--parts is required for generation.")
    if args.events < 1 or args.context_kib < 1:
        parser.error("Use positive event and context counts.")
    start = time.monotonic()
    total = 0
    with args.parts.open("w") as output:
        for index in range(1, args.events + 1):
            event = {
                "uuid": identifier(index),
                "info": "Synthetic large-feed event " + str(index),
                "Orgc": {"uuid": identifier(args.events + 1), "name": "Synthetic producer"},
                "date": "2026-11-09",
                "timestamp": "1794200000",
                "published": True,
                "distribution": 3,
                "Attribute": [
                    {
                        "uuid": identifier(args.events + index * 30 + item),
                        "type": "domain",
                        "value": f"host{item}.example.org",
                        "to_ids": True,
                    }
                    for item in range(20)
                ],
            }
            event["Attribute"].append(
                {
                    "uuid": identifier(args.events + index * 30 + 21),
                    "type": "text",
                    "value": secrets.token_hex(args.context_kib * 512),
                    "to_ids": False,
                }
            )
            result = misp_feed.handler(json.dumps({"data": [event], "feed_chunk": True}))
            if "error" in result:
                raise RuntimeError(result["error"])
            total += result["summary"]["uncompressed_bytes"]
            output.write(json.dumps(result) + "\n")
            if index % 1000 == 0:
                print(json.dumps({"generated": index, "seconds": round(time.monotonic() - start, 2)}), flush=True)
    print(
        json.dumps(
            {
                "events": args.events,
                "uncompressed_bytes": total,
                "seconds": round(time.monotonic() - start, 2),
                "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "parts": str(args.parts),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    run()
