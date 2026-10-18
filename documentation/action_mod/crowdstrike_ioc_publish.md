# CrowdStrike IOC Publish

`crowdstrike_ioc_publish` is a **workflow action** that publishes selected MISP
indicators to Falcon's custom IOC API. It creates new records and renews records
owned by this publisher. It uses the existing `crowdstrike-falconpy` dependency.
Existing MISP `file` and `domain-ip` objects suffice; no new templates are required.

## Set up

1. Create a Falcon API client with **IOC Management: Read and Write** permissions.
2. Configure `CROWDSTRIKE_CLIENT_ID` and `CROWDSTRIKE_CLIENT_SECRET` in the environment
   of the **misp-modules service**, then restart that service. Credentials are not
   accepted in the workflow payload. The service uses one configured client;
   choose the region belonging to that client.
3. Enable **CrowdStrike IOC Publish** and add it to an ad-hoc or event workflow that
   supplies the intended full event and object attributes. Configure its node
   parameters below. Only supplied attributes are considered; the module does not
   fetch missing event data from MISP.
4. Preview with `dry_run=true`, then use `dry_run=false` to publish. A dry run shows
   payloads but cannot identify ownership conflicts or validate tenant permissions.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `region` | `us1` | `us1`, `us2` or `eu1`; maps to Falcon's corresponding commercial API endpoint. Arbitrary URLs and government clouds are not supported. |
| `source` | `misp-modules` | Stable ownership namespace. Use a distinct value per MISP publisher. Accepts 1–64 ASCII characters, starting with a letter/digit, using letters, digits, spaces or `._:/-`. |
| `action` | `detect` | `detect` or `prevent`. Prevention is allowed only for MD5/SHA-256. A mixed prevention request containing domains/IPs is rejected before publication. |
| `severity` | `MEDIUM` | `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (case-insensitive). |
| `platforms` | `windows,mac,linux` | Non-empty comma-separated platform names; the API also accepts a list. |
| `host_groups` | Empty | Comma-separated Falcon host-group IDs, each 32 hexadecimal characters; the API also accepts a list. |
| `apply_globally` | `false` | Explicitly apply to the whole Falcon tenant. Either host groups or global scope is required; specifying both is rejected. |
| `expiration_days` | `30` | Integer 1–365. A successful publication renews expiry to this many days from the invocation. |
| `dry_run` | `false` | Return planned payloads without creating a client, authenticating, looking up or changing IOCs. |

Boolean parameters accept JSON booleans, integers 0/1, and strings `true`, `false`,
`1`, `0`. Empty strings use documented defaults. MISP displays parameter defaults
as placeholders; the module applies them when values are not supplied.

## Input and supported types

`data` may be a single standard event (`{"Event": {...}}`), a bare event, a legacy
envelope with `Attribute`/`Object` alongside `Event`, or a list of those events.
Event and object attributes are traversed. Only `to_ids=true` attributes are
eligible. Deleted events, objects and attributes are excluded.

| MISP type | Falcon type | Conversion |
| --- | --- | --- |
| `md5`, `sha256` | `md5`, `sha256` | Validate hexadecimal length and lowercase. |
| `domain`, `hostname` | `domain` | IDNA encode, lowercase, remove trailing DNS dot and validate DNS labels and Falcon's 200-character normalized domain limit. |
| `ip-src`, `ip-dst` | `ipv4`, `ipv6` | Validate and canonicalize the address. CIDRs and scoped IPv6 are excluded. |
| `domain\|ip` | Domain plus IP | Publish two independent atomic IOCs. |
| `filename\|md5`, `filename\|sha256`, `malware-sample` | File hash | Publish the hash component. Filenames containing pipes are handled by splitting at the last pipe. No sample data is uploaded. |

Other types, including URLs, SHA-1, filenames alone and port-qualified composites,
are skipped with counts in the result. Port constraints are not discarded to
create broader IOCs. Invalid values are skipped as malformed. Existing objects
need no special handling beyond their supported, IDS-marked attributes.

The 200-character domain limit applies after IDNA encoding, including to the domain
component of `domain|ip`. Overlong domains are counted as malformed before any
Falcon request, so otherwise eligible indicators can still be published successfully.

Indicators are deduplicated by canonical `(type, value)`. All contributing event,
attribute and object references remain in the returned `sources` list. Falcon's
description contains source event/attribute identifiers, limited to 500 characters;
free-text event titles, comments, MISP tags and binary data are not copied. The
description reflects the sources in the current invocation, not a complete history
of all MISP events that have ever supplied the IOC. MISP sharing policy and handling
markings must therefore be applied when selecting input data.

The action advertises `support_filters=false`: it processes its supplied events.
Requests containing `filteredItems` or `matchingData` are rejected rather than
silently publishing unfiltered data. Select the intended event data upstream.

## Ownership and updates

For each indicator the module queries Falcon IOC v1 by exact type/value, excluding
MSSP parent records. A record can be updated only if:

- Its `source` exactly matches the configured namespace.
- Its `tags` includes this module's fixed `misp-ioc-publish` marker.
- Its identity and returned ID are unambiguous and it is not a parent record.

New records receive both ownership fields. Foreign records, duplicate matches and
incomplete lookups produce failures without overwriting the matching IOC. Updating
owned records replaces their configured action, severity, scope, platforms,
description and expiration, while preserving existing Falcon tags. It is not an
adoption mechanism for existing manual or third-party records.

Re-running against a known owned IOC renews it instead of creating a duplicate.
Creation races or uncertain responses are reported as failures; the module does
not automatically retry writes. Deleted/non-IDS MISP attributes do **not** remove
existing Falcon records. Missing data is not a deletion instruction. Use Falcon
expiration or separate lifecycle administration for withdrawal.

## API example

POST this to the misp-modules `/query` endpoint for a preview:

```json
{
  "module": "crowdstrike_ioc_publish",
  "params": {
    "region": "eu1",
    "source": "MISP production",
    "action": "detect",
    "host_groups": "0123456789abcdef0123456789abcdef",
    "expiration_days": "30",
    "dry_run": "true"
  },
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "ip-dst",
        "value": "192.0.2.1",
        "to_ids": true
      }]
    }
  }
}
```

Responses contain `result_key=crowdstrike_ioc_publish` and a `data` summary with
`success`, `dry_run`, `created`, `updated`, `failed`, `planned`, `skipped` and `items`.
Each item identifies its canonical type/value, sources, outcome, and acknowledged
Falcon ID when available. Dry-run items additionally contain the planned payload.

Any lookup/write failure sets `success=false` and a top-level `error` with success
and failure counts. **Some indicators may already have been published.** Check
Falcon before retrying a request with an unknown outcome. HTTP 2xx alone is not
treated as publication success: API errors/warnings and missing acknowledgements
also fail. Provider error bodies and SDK exception text are not returned, preventing
accidental exposure of credentials from those messages.

MISP treats the top-level error as an action failure. The action is blocking so a
failed publication stops dependent workflow execution. On success, its summary is
available under `_env.misp_module_results.crowdstrike_ioc_publish`. On failure,
MISP may retain only the top-level error; standalone API clients receive the full
per-item summary as well.

## Limits and validation

At most **100 unique indicators** are accepted per invocation; larger inputs fail
before network access. Split larger jobs into smaller event selections. SDK calls
use a 15-second request timeout, and the module checks a 240-second processing
budget before each indicator and again before writing after lookup. Rate-limit
responses are reported without automatic retries. Remote writes are not rolled
back if another indicator fails or the calling workflow times out.

Tests use mocked Falcon responses and a real FalconPy client with mocked HTTP
transport. No live tenant changes are made by the tests; verify permissions,
regional availability and sensor behavior in your own deployment.
