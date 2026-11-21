# OCSF Event Import

Select **OCSF Event Import** (`ocsf_import`) to add Open Cybersecurity Schema
Framework events from a local file to a MISP event. The module accepts a
UTF-8 JSON object, a JSON array, or a newline-separated sequence of JSON
objects, including JSON Lines. Any of these formats can be gzip-compressed.

## Producer formats

| Producer or tool | Import path |
| --- | --- |
| Amazon Security Lake | Its native storage format is Parquet. Export the selected rows to JSON, for example with Athena `UNLOAD` using JSON and gzip, then import the export. Keep nested columns such as `metadata`, `src_endpoint` and `dst_endpoint`. [Security Lake format](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) · [Athena UNLOAD](https://docs.aws.amazon.com/athena/latest/ug/unload.html) |
| CrowdStrike Falcon Data Replicator | CrowdStrike documents a pipeline that maps selected Falcon data to OCSF and writes Parquet to Security Lake. Import its normalized OCSF rows after export to JSON. [CrowdStrike integration guide](https://github.com/CrowdStrike/aws-security-lake) |
| Okta, Falco and Zeek | The public OCSF mappings provide examples of identity and detection events, runtime findings and network telemetry. Import the normalized JSON output. [OCSF example mappings](https://github.com/ocsf/examples/tree/main/mappings) |

## Imported evidence

The importer creates one `ocsf-event` per record and links it to a `file`
object for the upload. The file object records the exact upload's SHA-256,
including gzip bytes when applicable. Enable `include_source` to attach the
upload. Install the companion `ocsf-event` template on the MISP server.

Every record needs a nonnegative integer `class_uid`, or its decimal string
representation. The importer accepts mixed classes and schema versions and
preserves extension fields. The original JSON is retained from each opening
brace to its closing brace. Larger events and events with literal non-ASCII
characters use numbered `raw-event-part` values. Decode the part objects and
concatenate their `text` values in ascending `part` order. `event-sha256`
covers the UTF-8 bytes of that JSON. Records with repeated producer IDs
retain separate positions.

The importer records class, category, activity, severity, status, product
and schema information when supplied. It selects an offset-aware `*_dt`
timestamp when present, with UTC epoch milliseconds as the fallback. When
both representations disagree by at least one millisecond, the projected
attribute and the response report the disagreement. The raw record retains
both source values.

The event also exposes selected fields from direct and finding evidence paths,
including source and destination addresses, hostnames, HTTP(S) URLs, user
names, command lines, reported file paths, and file hashes with a known
algorithm. Supported explicit scalar observables can add values even when the
producer uses an unfamiliar class. Each derived value cites its source path
in the attribute comment. Native MISP correlation is enabled for network
values and supported file fingerprints. Direction-neutral addresses use the
`ip-address` relation, whose MISP attribute type is `ip-dst` for value
correlation. All attributes have IDS disabled.

Uploads are limited to 10 MiB, 20 MiB after decompression, 1,000 records, and
512 KiB per record. The projection considers up to 128 entries per source
array and emits up to 64 distinct values per event. The full record is still
retained when a projection limit is reached. Invalid JSON, duplicate JSON
keys and invalid class IDs fail the upload with an error.

## Module API

```json
{
  "module": "ocsf_import",
  "filename": "security-events.jsonl.gz",
  "data": "<base64 file>",
  "config": {"include_source": false}
}
```
