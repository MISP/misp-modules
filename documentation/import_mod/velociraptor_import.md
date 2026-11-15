# Velociraptor results import

`velociraptor_import` imports **selected, offline result exports** from Velociraptor.
It accepts UTF-8 JSON (one row or an array), JSONL, and comma-separated CSV with
unique headers, including a UTF-8 BOM. JSONL and CSV are native Velociraptor result
formats. This module does not connect to a server, execute VQL, import collection
ZIPs, or retrieve paths/URLs mentioned in results. No API key is needed.

## Import through MISP or the module API

Enable **Velociraptor Results Import** in MISP's import-module settings. Download
the desired result table from Velociraptor, upload the JSON/JSONL/CSV file through
**Import from modules**, and supply its artifact/source and any collection context
missing from the rows. Review the returned objects before saving them to the event.

For example, export `Windows.System.Pslist`, then construct a `/query` request:

```python
import base64
import json
from pathlib import Path

path = Path("pslist.jsonl")
request = {
    "module": "velociraptor_import",
    "filename": path.name,
    "data": base64.b64encode(path.read_bytes()).decode("ascii"),
    "config": {
        "artifact": "Windows.System.Pslist",
        "server_id": "dfir-production",
        "client_id": "C.example",
        "flow_id": "F.example",
        "hostname": "workstation.example",
        "collected_at": "2026-11-15T10:00:00Z"
    }
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

Results are under `results.Object`. The module service does not itself save them
to MISP. Inspect the JSON `error` field even for an HTTP 200 response. Optional
`warnings` and `summary` fields describe retained but unmapped observations; MISP's
import interface may not display them. Errors return no partial `results`.

## Configuration and row context

| Setting | Default | Meaning |
| --- | --- | --- |
| `format` | `auto` | `json`, `jsonl`, `csv`, or automatic detection. JSON-shaped input is parsed as JSON/JSONL; other input as CSV. |
| `artifact` | empty | Artifact and optional source name. Required unless every row identifies its artifact. |
| `server_id` | empty | Analyst-supplied deployment identifier to distinguish independent servers. |
| `client_id` | empty | Default client identifier; do not use a single client default for a multi-host export lacking per-row identity. |
| `flow_id` | empty | Default collection/flow identifier. |
| `hunt_id` | empty | Default hunt identifier. |
| `hostname` | empty | Default endpoint hostname/FQDN, retained as non-correlating context. |
| `collected_at` | empty | Explicit collection time, applied to every row. Omit for multi-collection exports without a shared known collection time. Never inferred from import time. |

Non-empty row metadata takes precedence over the defaults:

| Context | Recognized row columns |
| --- | --- |
| Artifact/source | `_Source`, `Artifact`, `artifact` |
| Server/deployment | `ServerId`, `server_id` |
| Client | `ClientId`, `_ClientId`, `client_id` |
| Hostname | `Fqdn`, `Hostname`, `hostname` |
| Flow | `FlowId`, `_FlowId`, `flow_id` |
| Hunt | `HuntId`, `_HuntId`, `hunt_id` |

Column names are case-sensitive. Some aliases, such as `ServerId`, are optional
analyst-added columns rather than fields guaranteed by Velociraptor. Conflicting
aliases in a row reject the import. Missing context is not fabricated. A standard
single-artifact export commonly needs `config.artifact`; an annotated mixed export
can identify each artifact using `_Source`. No custom envelope is required.

## Mappings

Mappings follow these upstream artifact definitions:

| Artifact/source | Objects and fields |
| --- | --- |
| [`Windows.System.Pslist`](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/System/Pslist.yaml) | `process`: Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime. A linked executable `file` contains Exe and valid Hash.MD5/SHA1/SHA256. |
| [`Windows.System.Services`](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/System/Services.yaml) | `windows-service`: Name, DisplayName, PathName, StartMode, ServiceType. A related `file` uses AbsoluteExePath and HashServiceExe. The command line is not split to guess an executable. |
| [`Windows.Network.NetstatEnriched/Netstat`](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Network/NetstatEnriched.yaml), also the base artifact name | `network-socket`: Laddr, Lport, Raddr, Rport, Family, Type, Status. Row-local process/file context uses Pid, Ppid, Name, Path, CommandLine, Username and Hash. Local/remote endpoints map to source/destination fields; this does not assert who initiated the connection. |
| [`Windows.Search.FileFinder`](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Search/FileFinder.yaml) | `file`: OSPath, Size, Hash, BTime → creation-time, MTime → modification-time, ATime → access-time. Rows marked as directories are retained without file mapping. CTime remains raw metadata-change time. |

These are explicit profiles, not field-name heuristics for arbitrary artifacts.
Other artifact/source names remain `velociraptor-result` objects with a warning.
Projected or custom queries that rename columns may retain fewer mapped fields.
Nested Hash cells in native CSV must contain JSON; other nested/extension values
remain in their original row context. Invalid optional values are omitted from
typed mappings with warnings, while the original evidence remains available.

IPv4/IPv6 addresses, ports 0–65535, hash lengths and non-negative file sizes are
validated. Scoped IPv6 is retained only in the original row. Zero PIDs, sizes and
ports are not discarded. Process and file times require a complete timezone-qualified
instant at microsecond precision or less. Numeric epochs, timezone-free times,
invalid dates and higher precision timestamps remain in row/source evidence with
warnings rather than being guessed or truncated. Netstat's Timestamp is not mapped
to first-packet-seen, and service registry-key modification time is not asserted to
be service creation time.

## Provenance, relationships and repeat imports

One `file` object retains the exact original export as an attachment, its SHA-256,
basename and byte size. Every row becomes a `velociraptor-result` object with its
artifact/context, source hash, format, importer version, one-based record ordinal
and normalized row JSON. This JSON is a parsed representation: the attachment is
authoritative for original bytes, CSV quoting and JSON numeric precision.

The provenance row references its source file with `derived-from` and each mapped
observation with `describes`; mapped observations reference the row with
`derived-from`. Process executable files use `executes`; process/socket context
reported in the same row uses `related-to`. PIDs never join independent rows or
collections, so PID reuse cannot manufacture a process tree. Ppid remains a
`parent-pid` attribute. Repeated rows are distinct occurrences.

Object, attribute and reference UUIDs are deterministic for the same source bytes,
filename, record ordinal and resolved context. Changing those inputs can create
new identities. This supports repeat ingestion into an existing event; it does not
perform MISP server-side reconciliation or deduplicate differently exported files.
Supply `server_id` when independent deployments could share context identifiers.

All attributes have `to_ids=false`. Provenance fields and contextual text are
non-correlating; typed hashes/IPs follow their existing object template defaults.
An observed process, service or socket is not automatically malicious. Source
exports and raw rows can contain private endpoint information; select the input
and MISP sharing policy appropriate to the investigation.

The new [`velociraptor-result` template](https://github.com/MISP/misp-objects/tree/main/objects/velociraptor-result)
fills a row-level provenance gap. Existing process, file, network-socket and
windows-service templates are reused without modification. The module includes
the identical template so it can run before an updated PyMISP package is available.
Install/update the corresponding object template on the receiving MISP instance
to obtain the template in its UI.

## Limits and verification

Inputs are limited to 20 MiB, 1000 rows, 64 KiB per normalized row and 32 nesting
levels. Duplicate JSON keys, non-finite numbers, malformed CSV, conflicting context
and structural errors reject the whole import. Archives and uploaded file content
are outside this first version; Upload paths remain evidence context.

Run:

```sh
poetry run pytest -q tests/test_velociraptor_import.py
```

Tests use synthetic exports based on the upstream schemas, covering each profile,
native nested CSV cells, exact attachment bytes, cross-host identity, repeat
imports, unsupported data, time fidelity, limits, PyMISP object validation and the
module HTTP discovery/query contract. They do not claim a live Windows collection
or compatibility with every Velociraptor release/custom artifact.
