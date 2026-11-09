# OCSF Export

`ocsf_export` exports MISP indicators as UTF-8 NDJSON using **OCSF 1.9.0 OSINT
Inventory Info** (class `5021`, Discovery category `5`). This class describes
threat intelligence collected from sources such as MISP. Each line represents
one source attribute, with its indicators in the OCSF `osint` array.

The module uses the standard Python library and requires no remote service.
Restart misp-modules after installation to make `ocsf_export` available through
`/modules` and MISP's export interface.

## Request and output

Submit to the misp-modules `/query` endpoint:

```json
{
  "module": "ocsf_export",
  "config": {
    "include_non_ids": false,
    "misp_url": "https://misp.example"
  },
  "data": [
    {
      "Event": {
        "uuid": "example-event",
        "info": "Example intelligence",
        "Attribute": [
          {
            "uuid": "example-attribute",
            "type": "ip-dst",
            "value": "192.0.2.1",
            "to_ids": true,
            "Tag": [{"name": "tlp:green"}]
          }
        ]
      }
    }
  ]
}
```

The API response contains `response: []` and a base64-encoded `data` string.
Decode `data` to obtain an `.ndjson` file with one JSON event per line and a final
newline. There are no Elasticsearch Bulk action lines or enclosing JSON array.
For example, when the API response is saved as `response.json`:

```sh
python -c 'import base64,json; from pathlib import Path; r=json.loads(Path("response.json").read_text()); Path("indicators.ndjson").write_bytes(base64.b64decode(r["data"]))'
```

`include_non_ids` defaults to false. Set it to true to include supported contextual
attributes. Boolean settings accept JSON booleans, `0`/`1`, or strings
`"true"`/`"false"`/`"0"`/`"1"`.

`misp_url` is optional. It supplies the base URL for `osint[].src_url` event links,
including installations under a path. Credentials, query strings, and fragments
are rejected. It does not trigger an HTTP request.

Bare events, standard `{"Event": {...}}` wrappers, and legacy exports with
`Attribute`/`Object` alongside `Event` are accepted. All supplied events and object
attributes are processed. Deleted events, objects, and attributes are excluded.
Unsupported or malformed indicators are skipped with counts in API `warnings`.
Invalid request structures or settings return `error`. Empty exports return an
empty base64 payload.

## Indicator mappings

| MISP type | OCSF OSINT type | Value and context |
| --- | --- | --- |
| `ip-src`, `ip-dst` | IP Address (`1`) | Validated, normalized IPv4/IPv6 address |
| `domain` | Domain (`2`) | Domain value |
| `hostname` | Hostname (`3`) | Hostname value |
| `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512` | Hash (`4`) | Validated lowercase hex digest; original algorithm retained in `unmapped.misp.attribute.type` |
| `url` | URL (`5`) | Absolute URL with a host; supplied ports must be valid |
| `user-agent` | User Agent (`6`) | User agent string |
| `email-src`, `email-dst` | Email Address (`9`) | Email address value |
| `filename` | File (`11`) | Filename, also in `osint[].file.name` |
| `regkey` | Registry Key (`12`) | Registry key path |
| `domain\|ip` | Domain and IP Address | Two OSINT entries in the same source event |
| `ip-src\|port`, `ip-dst\|port`, `hostname\|port` | IP Address or Hostname | Atomic address/name plus integer `unmapped.misp.port` and a Port observable |
| `filename\|<hash>`, `malware-sample` | Hash (`4`) | Digest plus `osint[].file.name` and typed `file.hashes`; malware samples use MD5 |

Filename/hash composites split at the last `|`, preserving filenames that contain
that character. Ports must be in `0..65535`. IP networks and scoped IP addresses
are skipped. The module does not resolve hostnames, fetch URLs, or export attached
malware bytes. Unrecognized types are skipped rather than assigned an invented
OCSF indicator type.

`observables` exposes the corresponding OCSF observable type, value, and attribute
path, such as `osint[0].value`. OCSF represents both domains and hostnames with the
Hostname observable type (`1`); `osint[].type_id` distinguishes them. Consumers
must preserve composite port or filename/hash conditions when matching; individual
observable matches do not enforce a conjunction.

## Context, time, and lifecycle

Every event has `activity_id=2` (Collect), `type_uid=502102`,
`severity_id=1` (Informational), and `metadata.version="1.9.0"`. Inventory collection
severity does not rate the indicator's maliciousness. Confidence is Unknown (`0`);
MISP event threat level and arbitrary tags are not converted to confidence.

`time` and `metadata.processed_time` record collection/export time as UTC epoch
milliseconds. Attribute modification timestamps, with event timestamp as fallback,
map to `osint[].modified_time`. Numeric MISP timestamps are interpreted as epoch
seconds; timezone-aware ISO timestamps are also accepted. Invalid modification
times are omitted with a warning. `first_seen`/`last_seen` remain in source context:
observations do not establish creation or expiration, so those times are not invented.

Event, object, and attribute tags are combined into sorted `osint[].labels`.
The most restrictive recognized TLP tag supplies `osint[].tlp`. OCSF spells
AMBER+STRICT as **`AMBER STRICT`**. WHITE/CLEAR remain their original labels;
unmarked data stays unmarked. Raw tags are retained. TLP and MISP distribution
metadata describe handling restrictions; consumers must enforce their own access
controls.

`metadata.uid` is a stable digest of event, object, and attribute identifiers.
Numeric IDs are used when UUIDs are absent, with content as the final fallback.
Distinct sources stay separate; repeated sources in one export use the last
record. `metadata.original_event_uid` retains the event identifier;
`osint[].external_uid` retains the attribute identifier. Each OSINT component has
its own stable `uid`.

`unmapped.misp` preserves event/attribute identifiers, original type and value,
comments, source timestamps, observation times, creator organization, distribution
metadata, object context, and the IDS flag. These source details remain available
even when normalization changes the primary indicator value.

Import the decoded file through an OCSF consumer that supports **1.9.0 class
5021**. The module creates a file; it does not upload records, configure a SIEM,
or reconcile withdrawn indicators. Deleted or newly excluded indicators do not
produce deletion records. Consumers must implement retention, expiry, deduplication,
and cleanup. Tests validate emitted fields against an offline projection of the
published OCSF 1.9.0 JSON Schema, without optional profiles.
