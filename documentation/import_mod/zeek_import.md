# Zeek observation import

`zeek_import` imports already selected Zeek records. It complements outbound
[Zeek intelligence export](../export_mod/zeek_intel_export.md) with inbound evidence
mapping; it does not run Zeek, match intelligence, access a sensor or open captures.

Supported inputs are native UTF-8 JSON/JSONL or ASCII/TSV logs, optionally with a
BOM. TSV requires its `#separator`, `#path`, `#fields` and matching `#types` headers.
The parser respects hex escapes, set/vector separators, unset/empty markers, booleans
and concatenated header sections. Original lines, escaped columns, type/marker
headers and decoded values remain in each selected record's `raw-record`.

For JSON, specify `log_type` (for example `conn`, `dns`, `http`, `ssl`, `notice`,
`intel` or `files`) unless each record has explicit collector `_path` context.
Native Zeek JSON normally does not contain its stream name; the filename is not
used to guess it. JSON records must include `ts`. Arrays, single records and JSONL
are accepted. Unmapped stream/protocol fields remain raw rather than being classified
as malicious indicators or expanded into guessed entity types.

Use a normal import request with `module: "zeek_import"`, base64 source bytes in
`data`, optional `filename`, and these `config` values:

| Setting | Meaning |
| --- | --- |
| `format` | `auto` (default), `json`, `jsonl`, `tsv`. Explicit JSON does not silently accept JSONL. |
| `log_type` | Stream default for JSON. An explicit value must agree with a native TSV `#path`. |
| `timestamp_unit` | Numeric JSON epoch unit: `s` (default), `ms`, `us`, `ns`. TSV time columns always use seconds. |
| `sensor`, `tool_version` | Optional explicit producer context. Versions are not inferred from the importer. |
| `capture_file` | Optional source packet capture reference; never opened. |
| `capture_sha256` | Optional producer-supplied capture hash, distinct from the imported log's SHA-256. |
| `capture_url` | Optional capture/investigation link; never fetched. |
| `uids` | Optional comma-separated UIDs, or an API list, to retain. Default: all supplied records. |

Collectors may wrap records as JSON:

```json
{
  "metadata": {"log_type": "conn", "sensor": "sensor-a", "capture_file": "case.pcap"},
  "records": [
    {"ts": 1791633600.123456, "uid": "Cexample", "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.2", "proto": "tcp"}
  ]
}
```

Known metadata/config conflicts are errors. A per-record `_path` supplies stream
identity for combined JSON exports. `_capture_file` is an explicit collector
capture reference; if it overrides a different configured capture, the configured
hash/URL is not assigned to that other capture. A hash with a native/collector row
capture name requires matching `capture_file` context. Context supplied separately
is a producer claim and is not authenticated by the original log's hash.

Each record becomes a `network-observation`. Existing `network-connection` objects
retain validated originator/responder IPs, ports, transport and source-provided
Community IDs. `conn.ts` defines first-packet time; other stream timestamps are
observation times and are not labeled as connection starts. Durations remain raw:
Zeek JSON can expose floating-point tails, so an end time is not invented by
rounding a duration. Notices and symbolic signature IDs remain source context.

UIDs and Community IDs do not merge records. IDs are scoped to the sensor/capture/
run; Community ID seeds, versions, time scope and tuple direction must be considered
before comparing flows across sources. Only valid source-provided version-1 Community
IDs are promoted; unsupported values remain raw. No Community ID is computed with
an assumed seed.

Timestamp numbers are parsed as exact decimals, not binary floats. Units are
explicit, never guessed from magnitude; use the matching JSON timestamp mode if
Zeek was configured to emit milliseconds. Known-offset ISO dates, including Zeek's
ISO JSON mode, are also accepted. Local/unknown offsets, unsupported precision and
sub-microsecond values remain raw with warnings, without rounding. Decimal JSON
values retain their mathematical value in canonical raw records; original lexical
bytes remain in the source export.

All input is treated as an already selected export unless a UID filter is supplied.
The source `file` records the original export hash/size/name. If every record is
included, the exact source attachment is retained. If filtering excludes any record,
that full attachment is omitted with a warning; only selected raw records are included,
while the hash still refers to the original externally retained input. Source record
ordinals are retained rather than renumbered after selection.

Capture references use existing `pcap-metadata`; its name/hash describe only supplied
provenance, not a capture the importer inspected. Capture metadata points to the
source export and observations, and the export points to observations using the
catalogue's source-to-derived `derived-from` direction. Observations point to their
derived connections and also `describe` them. The compatible observation template
is bundled for older PyMISP inventories.

All attributes are non-IDS and non-correlating. Imported notices, protocol records
and signature matches remain `unreviewed`, separate from analyst-confirmed malicious
findings. No files/URLs referenced by source records are opened or fetched.

Limits: 20 MiB input, 1000 records before selection, 128 KiB per normalized record
and 32 nested levels. Invalid structures, duplicate JSON keys/TSV fields, schema
conflicts and invalid explicit settings return atomic errors. Corrupt mapped IDs,
IPs, ports and times remain raw with counted warnings. See
[fixture provenance](../../tests/fixtures/network_observation/README.md) for native
Zeek 9.0.1 validation and [Suricata import](suricata_import.md) for the companion flow.
