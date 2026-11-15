# Hayabusa / Chainsaw findings import

`evtx_findings_import` imports **detection outputs**, preserving rule metadata and
linked Windows event context. It does not run Hayabusa/Chainsaw, parse EVTX binaries,
read referenced paths, contact remote services or declare a host compromised.

## Supported exports

| Producer | Supported input |
| --- | --- |
| Hayabusa | Native JSON object streams, JSONL and comma-separated CSV timelines; JSON arrays/single objects with the same fields; built-in Timesketch profile column names |
| Chainsaw | `hunt --json` arrays or `hunt --jsonl`; `individual`, `cached` and `aggregate` detections with EVTX documents |

Hayabusa's native `-t json` output can contain several pretty-printed objects
without an enclosing array. `auto` recognizes this as `hayabusa-json`; it is not
assumed to be JSONL. Explicit `json` requires one complete JSON document; explicit
`jsonl` requires one object per non-blank line. `hayabusa-json` explicitly allows
the native Hayabusa object stream. Malformed/trailing input rejects the import.

Chainsaw's grouped CSV output can omit rule identifiers/severity and depends on
custom mapping columns. Use JSON/JSONL to preserve detection/event relationships.
Chainsaw search/dump output and binary EVTX uploads are not detection exports.

For Hayabusa 4.4.0, the `super-verbose` profile includes RuleID, Provider and EvtxFile.
For example:

```sh
hayabusa dfir-timeline -d evidence -w -p super-verbose -b -U -t jsonl -o findings.jsonl
chainsaw hunt evidence -s sigma --mapping mappings/sigma-event-logs-all.yml --json -o findings.json
```

Older Hayabusa releases use commands such as `json-timeline`/`csv-timeline`.
The importer consumes the exported fields rather than invoking these commands.
Check the producing version's help. Standard/minimal profiles may omit useful
context; missing rule IDs, provider names and EVTX references remain missing with
warnings. Channel/severity abbreviations are retained rather than expanded using
potentially different local configuration. `-b` disables producer abbreviations.

## Usage

Enable **Hayabusa and Chainsaw Findings Import** in MISP, upload the selected export
through **Import from modules**, then review the returned objects before saving.
For direct use of the module API, construct the request on the uploading client:

```python
import base64
import json
from pathlib import Path

path = Path("findings.jsonl")
request = {
    "module": "evtx_findings_import",
    "filename": path.name,
    "data": base64.b64encode(path.read_bytes()).decode("ascii"),
    "config": {"tool": "hayabusa", "format": "auto", "tool_version": "4.4.0"}
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

The response contains `results.Object`, `summary` and optional `warnings`. Inspect
the `error` field even with HTTP 200: invalid structure returns no partial results.
The module API does not itself save an event to MISP. The MISP UI may not display
the supplementary summary/warnings.

| Setting | Default | Meaning |
| --- | --- | --- |
| `tool` | `auto` | `hayabusa` or `chainsaw` enforces the selected schema. Automatic detection is per result, allowing explicitly identifiable mixed JSON arrays. |
| `format` | `auto` | `json`, `jsonl`, `hayabusa-json`, or `csv` (Hayabusa only). CSV headers must match the supported native/Timesketch profiles. |
| `tool_version` | absent | Producing tool version supplied by the analyst; not inferred. |
| `source_evtx` | absent | Optional EVTX reference applied only where a record lacks its own reference. Use it only when all such records share that source. No file is fetched. |

Inputs must be base64-encoded UTF-8, optionally with a UTF-8 BOM. Filenames are
reduced to a basename; `file` is not a server-side path to open.

## Preserved fields

| Information | Hayabusa | Chainsaw |
| --- | --- | --- |
| Rule title | RuleTitle; message in Timesketch profiles | name |
| Rule ID | RuleID, when present | id for Sigma rules; native Chainsaw rules may have no ID |
| Rule severity | Level | level |
| Rule maturity | Status | status; not an analyst verdict |
| Rule reference/source | RuleFile | source (`sigma` or `chainsaw`) |
| Detection/timeline time | Timestamp; datetime in Timesketch profiles | timestamp |
| Host / channel | Computer / Channel | document.data.Event.System.Computer / Channel |
| Provider | Provider | Event.System.Provider_attributes.Name |
| Windows Event ID / record ID | EventID / RecordID | Event.System.EventID / EventRecordID |
| Source EVTX | EvtxFile | document.path (or each aggregate document.path) |
| Windows event Level | Not inferred from rule Level | Event.System.Level; kept separate from rule severity |

Details, AllFieldInfo, ExtraFieldInfo, rule authors/tags, EventData and other
unmapped content remain in normalized raw-result/raw-event JSON. The exact source
export is attached with its SHA-256 and size. This hash identifies the **export**,
not any EVTX file it references. No rule ID, provider, host or record identifier is
invented. Invalid optional numbers/fields remain in raw evidence with warnings.

Event IDs are validated as 0–65535; record IDs as unsigned 64-bit integers. Zero
values and large integer record IDs are retained. A record ID is scoped to a log
and host and never used alone to join events.

Both event and detection timestamps retain their source strings. ISO timestamps
and Hayabusa's default `YYYY-MM-DD HH:mm:ss.sss +HH:MM` format are mapped to UTC
datetime fields only with a complete known offset and at most microsecond
precision. Numeric epochs, unknown offsets (`-00:00`), local times, alternate date
formats and nanosecond timestamps remain in raw fields without guessing units,
timezones or rounding. Source export bytes are authoritative for text/number
precision; PyMISP may trim surrounding whitespace from individual scalar attributes.

## Detection, evidence and analyst conclusions

Two focused templates preserve the different identities:

- `windows-event-log-detection`: one reported rule match, including rule ID/title,
  severity, tool, kind, source-result ordinal and normalized complete result.
- `windows-event-log-record`: one event context from that match. Chainsaw aggregate
  members remain separate objects, even if different hosts/logs share a record ID.
  For Hayabusa this is the timeline row's reported context, not a reconstructed
  binary EVTX record. Aggregated/composite IDs are kept raw rather than split into
  invented individual events.

The source export references both objects with `derived-from`; each event context
also references the detection based on it with `derived-from`. The detection points
to its event contexts with `describes`. This follows the relationship catalogue:
information in the **target** is based on information in the **source**.

Every imported detection has `review-status=unreviewed`, and every attribute has
`to_ids=false` and disabled correlation. A high severity rule match, stable rule
status or source verdict does not create an analyst-confirmed malicious finding,
galaxy attribution or sighting. Record an analyst's conclusion separately, for
example in a `threat-hunt-finding` object linked with `related-to`, after review.

An existing `detection` object describes an analytic's logic and response plan;
`python-evtx-event-log` requires event source/type/name fields not guaranteed here
and lacks an explicit record-ID relation. Neither can represent all this context
without invented fields or lost aggregate relationships. Existing templates are
unchanged. Both new templates are bundled for older PyMISP versions; update the
receiving MISP instance's templates to display them in the UI.

UUIDs for objects, attributes and references are stable for identical source bytes,
filename, result/member ordinal, resolved producer and explicit context. Repeated
occurrences stay distinct; differently exported files are not reconciled. Missing
cached event data or non-EVTX Chainsaw documents are preserved with warnings.

## Limits and validation

Limits: 20 MiB per export, 1000 detection results, 5000 event contexts, 256 KiB per
normalized result and 32 nesting levels. CSV also uses the Python CSV reader's
field-size limit. Duplicate JSON keys, non-finite numbers, malformed rows and
invalid structures reject the entire import. Archives and external references
are not opened.

```sh
poetry run pytest -q tests/test_evtx_findings_import.py
```

Fixtures include actual Hayabusa 4.4.0 and Chainsaw 2.17.1 outputs generated from
Chainsaw's public sample EVTX using benign test rules, plus a clearly labeled
synthetic aggregate. Tests cover native formats, rule versus event severity,
unreviewed status, cross-host aggregate scope, exact source bytes, deterministic
identity, timestamps, missing fields, malformed input, limits, PyMISP validation
and the HTTP discovery/query contract. See the fixture README for reproduction.
