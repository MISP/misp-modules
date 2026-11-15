# Timeline exchange fixture provenance

The fixture data is synthetic and contains no case evidence.

- `timesketch-api.json` is a schema-based Explore response with source IDs,
  wrapper timeline references, selection flags and source annotations. The two
  entries intentionally separate a starred/commented row from an explicitly
  selected row.
- `timesketch-cli.csv`, `.json`, `.jsonl` are produced by executing the unchanged
  upstream `Search.to_pandas` and CLI `format_output` functions against that
  synthetic API response, with pandas 3.1.0. Numeric JSON dates are milliseconds;
  the integer timestamp retains microsecond precision. CSV annotation cells use
  pandas' Python list/dict representation and the first message is multiline.
- `plaso.jsonl` is schema-adapted from Plaso's `tests/output/json_line.py`
  expected dictionary, including dfVFS parent evidence and EventTag metadata.
  It was not produced by running psort against a storage file.

Timesketch sources are pinned to
[`68392c22762c2de0dba391ff5b35219174b73df4`](https://github.com/google/timesketch/tree/68392c22762c2de0dba391ff5b35219174b73df4):

- `api_client/python/timesketch_api_client/search.py`
- `cli_client/python/timesketch_cli_client/commands/search.py`
- `timesketch/api/v1/resources/explore.py` and `exportstream.py` (schema review)
- `timesketch/lib/utils.py` (JSONL ingestion validator)

Plaso schema review used
[`fa7aeed9a48aa8ecbe532b69aa8c272ab232c624`](https://github.com/log2timeline/plaso/tree/fa7aeed9a48aa8ecbe532b69aa8c272ab232c624),
`plaso/output/json_line.py`, `shared_json.py`, and `tests/output/json_line.py`.

To reproduce CLI fixtures, install pandas and run `python reproduce.py` in this
directory. The script downloads only the pinned public source files, extracts the
two functions through AST and executes them without the API client or service.
`--upstream-dir` uses already fetched `timesketch-api-search.py` and
`timesketch-cli-search.py` instead.

`validate_upstream.py export.jsonl` similarly checks exported rows using the
unchanged pinned `read_and_validate_jsonl` function and its tag/scrubbing helpers.
It checks every emitted timestamp survives unchanged. It downloads the pinned
utility source or accepts `--source /path/to/timesketch-utils.py`; python-dateutil
is needed. This is a local format compatibility check, not a live service test.
