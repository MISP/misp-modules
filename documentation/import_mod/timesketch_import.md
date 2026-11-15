# Timesketch / Plaso selected findings import

`timesketch_import` imports entries that an analyst has selected, annotated or
prefiltered in a timeline. It complements the existing MISP Timesketch playbooks
with file exchange; no Timesketch API credentials or live service are required.

Supported inputs are UTF-8 (optional BOM):

- Timesketch Explore API JSON (`objects` with `_source` documents), OpenSearch
  search JSON (`hits.hits`), a flat JSON record/array, JSONL or CSV.
- Timesketch CLI search JSON, JSONL or CSV, preferably with internal columns
  enabled so that source document IDs and index references survive.
- Selected Plaso `psort -o json_line` output, including nested dfVFS `pathspec`,
  `date_time`, parser/data type and EventTag context. Native `.plaso` storage and
  other psort output formats are not supported. Apply selection with psort's
  event filter before exchanging the output.

Each record needs a non-empty `message` and a `datetime` or `timestamp` field.
`timestamp_desc` is preserved when supplied; missing descriptions are not
invented. Exporting back to Timesketch requires a description.

Submit a normal import request with `module: "timesketch_import"`, `data` holding
the base64-encoded export, and an optional `filename`. Configuration:

| Setting | Meaning |
| --- | --- |
| `format` | `auto` (default), `json`, `jsonl` or `csv`. Explicit formats are enforced. |
| `selection` | `all` (default), `selected` or `annotated`. |
| `datetime_unit` | Explicit unit for numeric `datetime`: `s`, `ms`, `us` or `ns`. Empty for ISO dates. |
| `sketch_id`, `timeline_id` | Optional source defaults when IDs are absent; row values, then applicable response `meta`, take precedence. |
| `source_url` | Optional source selection/event reference when absent from a row. Never fetched. |

`all` treats the supplied file as the analyst's prefiltered selection. Timesketch
Explore responses normally initialize `selected` to false; being a search hit
does not imply an explicit selection. `selected` requires a true selection flag.
`annotated` accepts non-empty source tags, labels or comments; it does not require
a selection flag. A Plaso EventTag container with an empty labels list is not an
annotation. Comments are available only if requested in the source export.
CSV annotation cells may contain JSON or pandas' Python list/dict representation;
the latter is parsed with `ast.literal_eval`, never executed. Parsed dictionaries
must have string keys, including nested dictionaries; malformed structures return
an atomic import error.

Explore response `meta.sketch_id`, singular `meta.timeline_id` and `meta.source_url`
are retained as source defaults even when no configuration repeats those values.
Per-entry references take precedence. Unrelated response metadata is not copied
into entries, so it cannot disclose excluded rows when selection is applied.

The importer reuses `timesketch-timeline`, with compatible version 4 additions
bundled for installations whose PyMISP templates are older. It preserves source
event/index/sketch/timeline references, annotation snapshots, source timestamp
values, parser/data type/display name, pathspec, complete normalized raw records
and the export SHA-256/row ordinal. Unmapped fields remain in `raw-event`.
Annotations remain source context: labels and tags are not applied as MISP tags,
and an annotation does not confirm malicious activity. All imported attributes
are non-IDS and non-correlating.

A linked `file` object records the export basename, SHA-256 and byte count.
When all rows are included it also contains the exact original export attachment.
When selection excludes any rows, that attachment is omitted with a warning so
excluded entries cannot leak into the event. The retained hash refers to the
original export bytes, which the analyst can retain separately; it is not the
hash of an EVTX file, disk image or other underlying evidence. The source file
points to derived timeline objects using the catalogue's `derived-from`
relationship direction.

`timestamp` always means integer microseconds since the Unix epoch, as defined
by Timesketch and Plaso. Numeric `datetime` units are never guessed from
magnitude. In particular, Timesketch CLI JSON/JSONL produced through pandas
normally requires `datetime_unit: "ms"`. If both values are present they must
agree, allowing the declared numeric date's quantization (for example, within
the same millisecond) while retaining the exact microsecond timestamp.

ISO dates require an explicit known offset and at most six fractional digits.
Local times, unknown `-00:00` offsets, conflicting timestamps, floats and
sub-microsecond dates remain raw with a warning and no normalized `datetime`.
They are not silently rounded or repaired; the exporter skips unresolved times.
Zero and negative epochs are supported. The input and normalized record limits
are 20 MiB, 1000 rows, 128 KiB per row and 32 nesting levels. Invalid structure,
duplicate JSON keys/CSV headers, conflicting IDs and invalid explicit settings
return an atomic error. No source path, URL or evidence file is opened.

For the return direction, see [Timesketch observations export](../export_mod/timesketch_export.md).

Format checks use pinned upstream Timesketch API/CLI functions and a Plaso
schema-adapted fixture; see [fixture provenance](../../tests/fixtures/timesketch/README.md).
