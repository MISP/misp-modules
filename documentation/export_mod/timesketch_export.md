# Timesketch timestamped observations export

`timesketch_export` produces UTF-8 JSONL for Timesketch's normal JSONL importer.
It complements existing Timesketch playbooks and accepts MISP events in standard
(`Event`), bare or legacy sibling-collection form, individually or as a list.
Pass only the event/attribute/object selection intended for exchange. The module
does not connect to Timesketch and does not write native Plaso storage.

It exports the following observations, including non-IDS forensic context:

| Source | Observation time |
| --- | --- |
| Existing `timesketch-timeline` objects | Consistent `datetime` / microsecond `timestamp`; requires `message` and `timestamp_desc`. |
| Existing `timesketch_message` objects | `datetime`, with the description `Timesketch message`. |
| `file` | `creation-time`, `modification-time`, `access-time`, `compilation-timestamp`. |
| `process` | `creation-time`, `start-time`. |
| `network-connection`, `network-socket` | `first-packet-seen`, `last-packet-seen`. |
| `windows-event-log-record`, `windows-event-log-detection` | `event-time`, `detection-time`, respectively. |
| Event-level and other object attributes | Explicit `first_seen` / `last_seen` endpoints; integer Unix seconds or ISO dates. |

Standalone `datetime` values without an observation meaning, event dates,
publication dates and MISP metadata modification `timestamp` values are not
treated as forensic activity. Deleted events, objects and attributes are excluded,
including serialized string deletion flags. Unsupported objects contribute only
their attributes' explicit first/last observations. Ambiguous repeated timeline
relations or invalid/unknown/local/sub-microsecond times are skipped and reported.
If nothing supported remains, the response is an error with a skip summary.

Each row contains mandatory `message`, UTC `datetime` and `timestamp_desc`, plus
an exact integer microsecond `timestamp`. Integer epoch arithmetic avoids float
rounding. The JSONL can be downloaded from MISP or decoded from the normal
base64 `data` response, then uploaded through Timesketch's JSONL import workflow.
The output extension is `.jsonl` with MIME type `application/x-ndjson`.

The additional `misp_*` columns contain event/object/attribute identifiers,
object name and relation, a deterministic observation ID, tag snapshots and
distribution/sharing-group metadata. Object references and an allowlist of visible
context fields (including source EVTX, event/record IDs and filenames) remain in
`misp_object_references` and `misp_context`. Optional module setting `misp_url` adds a
URL back to the MISP event; it must be an HTTP(S) base URL without credentials,
query or fragment. Metadata is descriptive and does not configure Timesketch
access control; choose the destination sketch and its access appropriately.

Imported source IDs, parser context and annotations are retained under
`misp_source_*`, including original export SHA-256 and row ordinal. Source tags,
comments, selection flags and labels are snapshots, not newly active Timesketch
annotations. Original `_id`, `_index` and `__ts_timeline_id` values are never
emitted as active ingestion metadata. Reimporting these JSONL rows with
`timesketch_import` recognizes their namespaced source references and annotations.

Attachments, malware samples' binary data and complete `raw-event` records are
excluded. Generic object messages summarize only identifying context (such as a
filename); first/last observations include the attribute's visible type/value.
At most 5000 observations and 20 MiB are emitted. The module makes no network
requests. Its deterministic IDs are custom metadata; repeated Timesketch uploads
can still create duplicate indexed events, and existing rows are not updated or
deleted remotely.

See [the importer guide](../import_mod/timesketch_import.md) for selection and
timestamp-unit details. Local validation uses the pinned upstream JSONL reader;
this does not assert live service, indexing or native psort execution coverage.
