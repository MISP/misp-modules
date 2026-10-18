# Elastic ECS export

`elastic_ecs_export` creates Elasticsearch **Bulk NDJSON** containing ECS 9.2
threat-indicator documents. It supports event attributes, object attributes and
event collections, without extra Python packages or an Elasticsearch connection.
Existing MISP object templates suffice; no new templates are required.

## Configuration and request

Enable **Elastic ECS Export** under MISP's export module settings.

| Setting | Default | Purpose |
| --- | --- | --- |
| `index` | `misp-indicators` | Target regular Elasticsearch index. Use 1–255 ASCII characters: start with a lowercase letter or digit, followed by lowercase letters, digits, dots, dashes or underscores. |
| `include_non_ids` | `false` | Include contextual attributes as well as `to_ids` indicators. Accepts booleans and strings `true`, `false`, `1`, `0`. |
| `misp_url` | Empty | Optional HTTP(S) MISP base URL for indicator references, including any deployment path prefix. |

`misp_url` must not contain URL credentials, including password-only or empty
userinfo. Authentication belongs in the consuming client's configuration.

The API accepts a list of standard MISP events (`{"Event": {...}}`), bare event
dictionaries, or legacy export envelopes with `Attribute` and `Object` alongside
`Event`. POST this request to `/query`:

```json
{
  "module": "elastic_ecs_export",
  "config": {"index": "misp-indicators", "misp_url": "https://misp.example"},
  "data": [{
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "info": "Example indicators",
      "Tag": [{"name": "tlp:clear"}],
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "ip-dst",
        "value": "192.0.2.1",
        "to_ids": true
      }]
    }
  }]
}
```

Decode the response's base64 `data` field and save it as `indicators.ndjson`.
Each document is preceded by a Bulk `index` action with `_index` and `_id`; the
file ends with a newline. It is **not** a document-only JSON-lines file or a Kibana
saved-objects export. An empty selection produces an empty file; do not submit an
empty file to `_bulk`.

Only `to_ids=true` attributes are included by default. Deleted events, objects and
attributes are always excluded. Unsupported types, malformed values and invalid
timestamp fields are counted in the API response's optional `warnings` list; the
MISP download UI may not display these warnings. An invalid optional timestamp is
omitted without dropping its valid indicator. Invalid request structure and
configuration return an `error` instead of partial output.

## Indicator fields

| MISP types | ECS `threat.indicator.*` fields | Indicator type |
| --- | --- | --- |
| `ip-src`, `ip-dst` | `ip` | `ipv4-addr` or `ipv6-addr` |
| `domain`, `hostname` | `url.domain` | `domain-name` |
| `url` | `url.full`, parsed `url.domain`, `url.scheme`, optional `url.port` | `url` |
| `email-src`, `email-dst` | `email.address` | `email-addr` |
| `filename` | `file.name` | `file` |
| `md5`, `sha1`, `sha256`, `sha384`, `sha512` | `file.hash.<algorithm>` | `file` |
| `AS` | `as.number` (integer) | `autonomous-system` |
| `ip-src\|port`, `ip-dst\|port`, `hostname\|port` | Corresponding indicator plus integer `port` | IP or domain type |
| `filename\|<supported hash>`, `malware-sample` | `file.name` and `file.hash.<algorithm>` in one document | `file` |
| `domain\|ip` | Separate domain and IP documents retaining the same source attribute UUID | Domain and IP types |

IP addresses are validated and canonicalized; CIDRs and scoped IPv6 addresses are
excluded because ECS's `ip` field requires a single address. Hashes require the
correct hexadecimal length and are lowercased. Ports must be 0–65535, AS numbers
0–4294967295, and URLs absolute with a host. Filenames may contain pipes: composite
file values split at the last pipe. Binary attachment data is never exported.
Domains, email addresses and filenames otherwise retain their supplied spelling;
apply any additional validation and normalization required by your telemetry.

## Provenance, markings and time

Each document has `ecs.version=9.2.0`, `event.kind=enrichment`,
`event.category=["threat"]`, `event.type=["indicator"]` and
`event.dataset=misp.indicator`.

`@timestamp` records when this enrichment document was exported. Source attribute
modification time (or the event timestamp as fallback) maps to
`threat.indicator.modified_at`. Explicit attribute observations map to
`threat.indicator.first_seen` and `last_seen`. Dates are converted to UTC RFC 3339
with millisecond precision; timezone-free strings are omitted with a warning.
Observation times are not expiry times; no validity deadline is invented.

Source event/attribute identifiers, raw values, distribution metadata, object
context and raw observation times are retained under the custom `misp` namespace.
The starter template maps this namespace as `flattened`, avoiding uncontrolled
field creation. `threat.indicator.id` retains the attribute UUID when supplied;
`event.id` equals the generated Bulk document ID. The creator organization supplies
`threat.indicator.provider`, falling back to `MISP`.

Event, object and attribute tags are combined into a sorted `tags` array. The most
restrictive recognized TLP tag supplies `threat.indicator.marking.tlp`: RED,
AMBER+STRICT, AMBER, GREEN, CLEAR/WHITE. Version is set only when the label identifies
it unambiguously: WHITE is TLP 1.0; CLEAR and AMBER+STRICT are TLP 2.0. Unmarked data
stays unmarked. `confidence` is `Not Specified`; event threat level and arbitrary
confidence tags are not converted into confidence ratings. All supplied tags remain
available. These markings are metadata, not Elasticsearch access controls.

Bulk IDs derive from event, object and attribute UUIDs (numeric IDs as fallback)
plus component position. Repeated imports update documents with the same IDs;
distinct sources remain separate. With missing identifiers, content is used as a
fallback and changing that content can create a new ID. If a source appears more
than once in an export, its last document wins. Changing a composite's shape can
leave an earlier component behind. Deleted, withdrawn or newly excluded indicators
do not generate deletion actions: consumers must handle expiry and cleanup.

## Import and match

Install [the starter index template](elastic_ecs_export_template.json) **before**
creating the target index. Its field types were checked against ECS v9.2.0. Adjust
`index_patterns` when using a target outside `misp-indicators*`, and review any
existing templates that apply to the same index. It maps the indicator IP as `ip`,
dates as `date`, ports/AS numbers as `long`, and matching strings as ECS keyword or
wildcard fields. Unknown fields are retained in `_source` but not dynamically indexed.

Keyword, wildcard and flattened mappings set `ignore_above=4096` characters, leaving
room below Lucene's term byte limit for four-byte UTF-8 values and flattened key
prefixes. Longer values remain intact in `_source` but are not indexed or available
for matching through these fields. This prevents oversized comments, tags, URLs or
raw provenance values from rejecting the entire indicator. Updating a template
only affects indices created afterward; apply equivalent mapping updates to an
existing target index or create a new index before importing.

For example, with authenticated access configured for your Elasticsearch endpoint:

```sh
curl --fail-with-body "$ELASTICSEARCH_URL/_index_template/misp-indicators" \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @elastic_ecs_export_template.json
curl --fail-with-body "$ELASTICSEARCH_URL/_bulk" \
  -X POST -H 'Content-Type: application/x-ndjson' \
  --data-binary @indicators.ndjson
```

Check the Bulk response's **`errors` flag and every item**; HTTP 200 can include
failed documents. Split large exports into batches at action/document pair
boundaries. The exporter targets regular indices using `index` operations, not data
streams that require `create` operations. It does not upload data itself.

In an Elastic Security indicator-match rule, select `misp-indicators*` as the
indicator index, filter to `event.dataset: "misp.indicator"`, and map your telemetry
fields, for example:

| Telemetry field | Indicator field |
| --- | --- |
| `destination.ip` or `source.ip` | `threat.indicator.ip` |
| `dns.question.name` | `threat.indicator.url.domain` |
| `url.full` | `threat.indicator.url.full` |
| `file.hash.sha256` | `threat.indicator.file.hash.sha256` |

Choose a suitable indicator time range using `@timestamp`, and refresh exports
deliberately: re-exporting old source intelligence refreshes its export timestamp.
A single atomic match does not enforce a composite port or filename/hash
conjunction. Add those conditions to your detection if required. This module does
not install rules, reconcile indicator lifecycle, or imply that domains match every
URL or subdomain. Validate the template, import and rules against your deployment.
