# osquery results import

`osquery_import` completes the return path from [OSQuery Export](../export_mod/osqueryexport.md)
and [OSQuery Pack Publish](../action_mod/osquery_pack_publish.md). It imports
already collected results without executing SQL or contacting endpoints. Save the
exporter's `sources` map alongside the deployed query pack: native osquery logs
carry query identity, but do not contain the originating MISP indicator references.

Supported inputs are UTF-8 JSON/JSONL (optional BOM):

| Native format | Meaning |
| --- | --- |
| `action: added/removed` with `columns` | One differential row per event log record. |
| `diffResults: {added: [...], removed: [...]}` | Batched differential rows, emitted with `logger_event_type=false`. |
| `action: snapshot` with `snapshot: [...]` | Full snapshot array, including an empty array. |
| `action: snapshot` with `columns` | One snapshot row per event when `logger_snapshot_event_type=true`. |

Single records, arrays of native records and newline-delimited records are
accepted. JSON `null` rows and ambiguous payloads are invalid. Native snapshot
event logging emits no record for an empty result, so that absence cannot be
imported as an execution or a no-match conclusion. An explicitly empty full
snapshot or batch becomes `record-type: empty-result`, with no invented row.

Normal import requests use `module: "osquery_import"`, the base64 export in `data`,
an optional `filename`, and the following `config` values:

| Setting | Meaning |
| --- | --- |
| `format` | `auto` (default), `json` or `jsonl`. Explicit JSON does not silently accept JSONL. |
| `input_type` | `auto` for native logger formats; `snapshot` for explicitly identified ad-hoc row arrays such as `osqueryi --json` output. |
| `host_identifier` | Fallback only when native `hostIdentifier` is absent; required for ad-hoc rows. A host identifier may be a UUID or custom value, not a hostname. |
| `query_name` | Query identity for ad-hoc rows. If supplied with native logs, it must agree with the full scheduled name or recognized bare query key. |
| `pack_name` | Optional pack context for arbitrary scheduled names. |
| `executed_at` | Optional known-offset ISO execution time when native `unixTime` is absent; never defaults to import time. |
| `osquery_version` | Optional producer-supplied version. |
| `sources` | The JSON `sources` map from hunting export/publication, as an object through the API or a JSON string through the UI. |

Native host/query values take precedence over fallback context. Ad-hoc rows are
never identified by guessing that row columns named `host`, `name`, `pid` or
`misp_attribute_uuid` represent provenance. Empty ad-hoc arrays are accepted only
with explicit snapshot mode and host/query context. Ad-hoc numeric/string values
remain as emitted by the source; for example, osqueryi may serialize numbers as
strings while a numeric-enabled daemon logger emits JSON numbers.

Collectors can bundle context and references in a file rather than config:

```json
{
  "metadata": {"pack_name": "misp-indicators", "osquery_version": "5.24.1"},
  "sources": {
    "misp_<query hash>": [
      {"event": "<event UUID>", "object": "<optional object UUID>", "attribute": "<attribute UUID>", "misp_type": "filename"}
    ]
  },
  "results": [
    {"name": "pack_misp-indicators_misp_<query hash>", "hostIdentifier": "host-uuid", "unixTime": 1794744000,
     "action": "added", "columns": {"path": "/example/indicator"}}
  ]
}
```

Use the real exporter-generated query key and source references. `osqueryexport`
returns `sources` beside its base64 pack `data`; `osquery_pack_publish` returns
it under `data.sources`. Neither requires changes to osquery's pack schema.
Metadata/config conflicts and conflicting copies of a source-map entry are errors.
An exact full scheduled-name entry in `sources` takes precedence over a bare query
key. Multiple event/object/attribute origins for one deduplicated query remain a
single structured reference array, preserving the association between those IDs.

The full native scheduled name is always retained. For the existing exporter's
`misp_` plus 64-digit hash keys, a standard `pack_<pack>_<query>` name can be split
unambiguously, including pack names containing underscores. Arbitrary pack/query
names are not split by guessing: provide `pack_name` or key sources by the exact
scheduled name. Custom osquery pack delimiters likewise require explicit context
or exact-name mapping. Contradictory MISP pack hints are rejected. Without a source
entry, a MISP-generated query produces a warning; origins are not decoded from a
hash or inferred from returned values.

Each real row becomes an `osquery-result`; a source `file` retains the exact
original attachment, filename, SHA-256 and byte count. The file points to derived
results with the catalogue's `derived-from` relationship. The importer bundles a
compatible template for older PyMISP inventories. All attributes are non-IDS and
non-correlating. Generic rows stay intact rather than being classified into entity
types from ambiguous column names.

Result objects retain host, query/pack, execution time, epoch/counter (including
zero), action, decorations, exact column types, source references and unmodeled
metadata. `record-index` identifies the source log line/record; `row-index` counts
rows within a snapshot/batch expansion. `row-count` is per source record: an event
format row does not tell us the total query row count. Empty results have no row or
row index. Duplicate rows across hosts, executions and source records remain
separate observations; the importer does not reconstruct endpoint state.

Native `unixTime` explicitly means integer Unix **seconds**. It is normalized
without floats or magnitude-based unit guessing; zero and negative representable
epochs are supported. Invalid numeric/overflow values stay raw with a warning and
do not fall back to a different time. `calendarTime` is preserved as display context,
not parsed with a guessed locale/timezone. Collector dates require a known offset
and at most six fractional digits; local, unknown `-00:00` or higher-precision times
remain raw. Schedule `epoch` is an execution-generation marker, not an observation
timestamp. Query execution/log time is not an entity creation/deletion time.

Results start as `unreviewed`. An `added` row may be the initial baseline, and a
`removed` row only describes a differential: it does not prove remediation, delete
MISP attributes or retract a source indicator. Empty results are not automatically
benign verdicts. The existing hunting exporter disables removed-row logging by
default; enable it in the deployed pack if those differentials are needed. Missing
log records do not imply removal or query success. Source references are retained
as provenance, without fetching or modifying the original event/attributes.

Limits are 20 MiB result input, 1000 source records, 1000 expanded rows/empty-result
objects, 128 KiB per normalized row/record context/reference list, and 32 nesting
levels. Source maps allow 1000 query keys and 1000 references per key, at most
20 MiB total. Invalid structures, duplicate JSON keys, non-finite numbers and
invalid explicit settings return atomic errors. No SQL, paths or URLs are opened.

Native-format validation uses actual osquery **5.24.1** daemon and shell outputs
from an isolated synthetic query pack. See [fixture provenance](../../tests/fixtures/osquery/README.md).
