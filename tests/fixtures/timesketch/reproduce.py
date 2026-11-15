"""Reproduce CLI fixtures with pinned upstream functions, without a Timesketch service.

Run with --upstream-dir containing timesketch-api-search.py and
timesketch-cli-search.py fetched from the pinned revision below, or omit it to
download those public sources. pandas is required only for reproduction.
"""

import argparse
import ast
import copy
import json
import types
import urllib.request
from pathlib import Path

REVISION = "68392c22762c2de0dba391ff5b35219174b73df4"
SOURCES = {
    "api": "api_client/python/timesketch_api_client/search.py",
    "cli": "cli_client/python/timesketch_cli_client/commands/search.py",
}


def upstream_function(source, name, globals_):
    tree = ast.parse(source)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), node],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(module), "upstream", "exec"), globals_)
    return globals_[name]


def main():
    import pandas

    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path)
    args = parser.parse_args()
    sources = {}
    for kind, path in SOURCES.items():
        if args.upstream_dir:
            sources[kind] = (args.upstream_dir / f"timesketch-{kind}-search.py").read_text()
        else:
            url = f"https://raw.githubusercontent.com/google/timesketch/{REVISION}/{path}"
            sources[kind] = urllib.request.urlopen(url, timeout=30).read().decode()
    directory = Path(__file__).parent
    response = {
        "meta": {"sketch_id": 7},
        "objects": [
            {
                "_id": "event-1",
                "_index": "source-index",
                "__ts_timeline_id": 12,
                "selected": False,
                "_source": {
                    "datetime": "2026-10-10T12:00:00.123456+00:00",
                    "timestamp": 1791633600123456,
                    "timestamp_desc": "Content Modification Time",
                    "message": "Example file changed\nsecond line",
                    "label": ["__ts_star"],
                    "tag": ["reviewed"],
                    "comment": [
                        {"comment": "Investigate this entry", "user": "analyst", "created_at": "2026-10-11T09:00:00Z"}
                    ],
                    "parser": "filestat",
                    "data_type": "fs:stat",
                    "display_name": "OS:/evidence/example.txt",
                },
            },
            {
                "_id": "event-2",
                "_index": "source-index",
                "__ts_timeline_id": 12,
                "selected": True,
                "_source": {
                    "datetime": "2026-10-10T12:00:01+00:00",
                    "timestamp": 1791633601000000,
                    "timestamp_desc": "Creation Time",
                    "message": "Selected example",
                    "label": [],
                    "tag": [],
                    "comment": [],
                    "parser": "filestat",
                    "data_type": "fs:stat",
                    "display_name": "OS:/evidence/second.txt",
                },
            },
        ],
    }
    (directory / "timesketch-api.json").write_text(json.dumps(response, indent=2) + "\n")
    to_pandas = upstream_function(sources["api"], "to_pandas", {"pandas": pandas})
    format_output = upstream_function(sources["cli"], "format_output", {})
    sketch = types.SimpleNamespace(list_timelines=lambda: [types.SimpleNamespace(id=12, name="Evidence timeline")])
    search = types.SimpleNamespace(
        return_fields="label,message,datetime,timestamp,timestamp_desc,comment,tag,_id,_index,_source", _sketch=sketch
    )
    search.to_pandas = types.MethodType(to_pandas, search)
    for kind in ("csv", "json", "jsonl"):
        search._raw_response = copy.deepcopy(response)
        output = format_output(search, kind, True, True)
        (directory / f"timesketch-cli.{kind}").write_text(output)
    # Schema-adapted Plaso fixture, based on tests/output/json_line.py's expected_json_dict.
    plaso = {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "date_time": {
            "__class_name__": "PosixTimeInMicroseconds",
            "__type__": "DateTimeValues",
            "timestamp": 1340821021000000,
        },
        "timestamp": 1340821021000000,
        "timestamp_desc": "Unknown",
        "message": "Example session closed for user root",
        "data_type": "test:event",
        "parser": "test",
        "display_name": "TSK:/var/log/syslog.1",
        "hostname": "ubuntu",
        "pathspec": {
            "__type__": "PathSpec",
            "type_indicator": "TSK",
            "location": "/var/log/syslog.1",
            "inode": 15,
            "parent": {"__type__": "PathSpec", "type_indicator": "OS", "location": "/cases/image.dd"},
        },
        "tag": {"__container_type__": "event_tag", "__type__": "AttributeContainer", "labels": ["Malware", "Printed"]},
    }
    (directory / "plaso.jsonl").write_text(json.dumps(plaso) + "\n")


if __name__ == "__main__":
    main()
