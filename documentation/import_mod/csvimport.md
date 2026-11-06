# Import CSV through the REST API

Send `csvimport` requests to misp-modules' `/query` endpoint with the
**base64-encoded UTF-8 CSV contents in `data`**. A `file` field does not tell the
server to open that path. Read and encode the file on the client that sends the
request. This also works when the client and misp-modules run on separate hosts.

For example, save the following as `indicators.csv`, without a header line:

```csv
192.0.2.1,Example indicator
192.0.2.2,Another indicator
```

Build a JSON request with Python, mapping the two columns to `ip-dst` and
`comment`:

```bash
python3 - indicators.csv > body.json <<'PY'
import base64
import json
import sys
from pathlib import Path

request = {
    "module": "csvimport",
    "data": base64.b64encode(Path(sys.argv[1]).read_bytes()).decode("ascii"),
    "config": {
        "header": "ip-dst,comment",
        "has_header": False,
        "special_delimiter": ","
    }
}
print(json.dumps(request))
PY

curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data-binary @body.json http://127.0.0.1:6666/query
```

Replace the URL with the service address configured in your installation.
The response contains imported attributes under `results.Attribute` and objects,
when present, under `results.Object`. It does not by itself save them to a MISP
event. Module errors appear under `error`, including in HTTP 200 responses;
inspect the JSON rather than relying only on curl's exit status.

## CSV mapping options

- `header`: a comma-separated list of MISP types or attribute fields, regardless
  of the delimiter used in the file. Use an empty field, whitespace or `_` to
  ignore a column. For example, `,ip-dst,ip-dst|port,,datetime,malware-type`
  skips the first and fourth columns. Each unskipped type must be recognised by
  the MISP attribute schema installed with PyMISP.
- `has_header`: accepts JSON `true`/`false`, integers `1`/`0`, or strings
  `"1"`/`"0"`. It defaults to false. Set it to true to skip the first non-comment
  row when supplying a mapping, or use that row as the mapping if `header` is
  omitted or blank.
- `special_delimiter`: defaults to a comma when omitted, null or empty. Specify
  `";"`, a tab (`"\t"` in JSON), or another delimiter when needed. Single-character
  delimiters support CSV quoting; the existing multi-character delimiter mode
  splits literal values and does not implement CSV quoting.

For a file that begins with `ip-dst,comment`, the request can omit both optional
string settings and use `"config": {"has_header": true}`. Without a header row,
provide a nonempty `config.header` mapping. Lines beginning with `#` are ignored.

The uploaded contents must decode as UTF-8; a UTF-8 BOM and line-wrapped base64
are accepted. Missing data, invalid base64/UTF-8, invalid options and inputs with
no data rows return module errors with guidance.

This addresses the request-format confusion in
[issue #604](https://github.com/MISP/misp-modules/issues/604). The module imports
uploaded contents; it does not provide server-side file access.
