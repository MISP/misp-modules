"""Manual local compatibility check using the pinned Timesketch JSONL reader."""

import argparse
import ast
import datetime
import io
import json
import logging
import types
import urllib.request
from pathlib import Path

from dateutil import parser
from reproduce import REVISION, upstream_function


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument("export", type=Path)
    arguments.add_argument("--source", type=Path)
    args = arguments.parse_args()
    if args.source:
        source = args.source.read_text()
    else:
        url = f"https://raw.githubusercontent.com/google/timesketch/{REVISION}/timesketch/lib/utils.py"
        source = urllib.request.urlopen(url, timeout=30).read().decode()
    tree = ast.parse(source)
    removed = next(
        n
        for n in tree.body
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "FIELDS_TO_REMOVE" for t in n.targets)
    )
    globals_ = {
        "json": json,
        "datetime": datetime,
        "parser": parser,
        "logger": logging.getLogger("upstream"),
        "errors": types.SimpleNamespace(DataIngestionError=ValueError),
        "FIELDS_TO_REMOVE": ast.literal_eval(removed.value),
    }
    upstream_function(source, "_parse_tag_field", globals_)
    globals_["_scrub_special_tags"] = upstream_function(source, "scrub_special_tags", globals_)
    read = upstream_function(source, "read_and_validate_jsonl", globals_)
    text = args.export.read_text()
    expected = [json.loads(line) for line in text.split("\n") if line]
    actual = list(read(io.StringIO(text)))
    assert actual == expected, "Upstream reader changed or rejected exported content"
    assert all(isinstance(row["timestamp"], int) for row in actual)
    print(f"Upstream Timesketch JSONL reader accepted {len(actual)} observations unchanged")


if __name__ == "__main__":
    main()
