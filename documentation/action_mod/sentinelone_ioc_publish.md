# SentinelOne IOC Publish

`sentinelone_ioc_publish` is a **workflow action** that publishes selected MISP
indicators to SentinelOne's Threat Intelligence database. Publishing uses the
native v2.1 IOC API with explicit account or site scope. Threat Intelligence
publication does not automatically add indicators to an endpoint blocklist.
The module uses the existing `requests` dependency. Existing MISP `file` and
`domain-ip` objects suffice; no new object templates are required.

## Set up

1. Create a SentinelOne API token with **Threat Intelligence.view** and
   **Threat Intelligence.manage** permissions for the intended account or site.
2. Set `SENTINELONE_URL` to your HTTPS console origin, for example
   `https://your-console.sentinelone.net`, and set `SENTINELONE_API_TOKEN` in the
   environment of the **misp-modules service**. Restart that service. The URL must
   not include credentials, an API path, a query or a fragment. Workflow parameters
   cannot override the console URL or token.
3. Enable **SentinelOne IOC Publish** and add it to an event or ad-hoc workflow
   supplying the intended full event and object attributes. Configure a single
   account or site below. The module does not fetch missing event data from MISP.
4. Preview with `dry_run=true`, then set `dry_run=false` to publish. Dry runs need
   no credentials and make no network requests; they cannot verify API permissions
   or identify existing records.

Some SentinelOne deployments reject multi-account tokens with error `4030010` even
when requests contain explicit account/site filters. Use a service user limited to
the intended account or site and verify its Threat Intelligence permissions.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `scope` | Required | `account` or `site`. Tenant-wide and group publication are not supported. |
| `scope_id` | Required | A single account or site ID, supplied as an 18–20 digit string. |
| `source` | `misp-modules` | Stable publisher namespace. Use a distinct value per MISP publisher. Accepts 1–64 ASCII characters, starting with a letter/digit, using letters, digits, spaces or `._:/-`. |
| `expiration_days` | `14` | Integer 1–180. Any input containing an eligible IP indicator requires 30 or fewer days; split mixed inputs to use longer expiry for other types. Applies to newly created records only. |
| `severity` | `4` | Integer 0–7, applied to newly created records. |
| `dry_run` | `false` | Return scoped creation payloads without authentication, lookups or writes. |

Booleans accept JSON booleans, integers 0/1 and strings `true`, `false`, `1`, `0`.
Empty optional parameters use the documented defaults. MISP displays defaults as
placeholders; the module also applies them when values are not supplied.

## Input and supported types

`data` accepts a standard event (`{"Event": {...}}`), a bare event, a legacy
envelope with `Attribute`/`Object` alongside `Event`, or a list of these events.
Only supplied, non-deleted attributes with `to_ids=true` are eligible. Deleted
events and objects are excluded.

| MISP type | SentinelOne type | Conversion |
| --- | --- | --- |
| `md5`, `sha1`, `sha256` | `MD5`, `SHA1`, `SHA256` | Validate hexadecimal length and lowercase. Empty-file hashes are excluded because SentinelOne rejects them. |
| `domain`, `hostname` | `DNS` | IDNA encode, lowercase, remove a trailing DNS dot and validate DNS labels and the 253-character normalized name limit. |
| `url` | `URL` | Require an absolute URL with a host, valid port and no whitespace; preserve its exact value. |
| `ip-src`, `ip-dst` | `IPV4`, `IPV6` | Validate and canonicalize. CIDRs and scoped IPv6 are excluded. |
| `domain\|ip` | DNS plus IP | Publish two independent atomic indicators. |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `malware-sample` | File hash | Publish only the hash component, splitting at the last pipe. No filename or sample data is uploaded. |

All indicators use the API's `EQUALS` matching method. Unsupported types, including
email addresses, filenames alone and port-qualified composites, are skipped with
counts. Port constraints are not discarded to create broader indicators. Invalid
supported values are counted as malformed and skipped; malformed input containers
and invalid configuration fail before network access.

Canonical `(type, value)` pairs are deduplicated. All contributing event, attribute
and object references remain in each result's `sources` list. The remote description
contains event/attribute identifiers, limited to 500 characters. Free-text titles,
comments, tags and binary data are not copied. Select input according to the MISP
event's sharing policy and handling markings.

The action advertises `support_filters=false`. Requests containing `filteredItems`
or `matchingData` fail to avoid publishing unintended unfiltered data. Select the
intended events upstream.

## Identity and lifecycle

A deterministic UUID `externalId` is derived from scope, scope ID, source, type and
canonical value. The same observable supplied by several MISP attributes therefore
has one publisher identity. Changing the source or scope creates a different
identity; keep those settings stable.

Before creation, the module looks up the external ID within the configured scope.
An existing record is accepted only when its source, external ID, type, value,
matching method and exact scope agree, and its expiry is valid and in the future.
Incomplete lookups, multiple matches and mismatches fail without writing. A new
record is counted as created only after a matching scoped acknowledgement with a
remote UUID is received.

The native IOC API exposes **no update endpoint**. Existing matching records are
reported as `existing` and left unchanged, including expiry, severity and source
description. Re-running does not renew their lifetime. Expired or invalid-expiry
records fail and require lifecycle administration in SentinelOne. The module does
not delete/recreate records. Deleted or non-IDS MISP attributes do not withdraw
remote indicators; use expiry or separate SentinelOne administration.

Lookup and creation are separate operations. Concurrent invocations can race, and
the external ID is a correlation mechanism rather than a guarantee of exactly-once
creation. Writes are never automatically retried. Inspect SentinelOne before
retrying any request whose remote outcome is unknown.

## API example

POST this request to the misp-modules `/query` endpoint for a preview:

```json
{
  "module": "sentinelone_ioc_publish",
  "params": {
    "scope": "account",
    "scope_id": "225494730938493804",
    "source": "MISP production",
    "expiration_days": "14",
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

Responses contain `result_key=sentinelone_ioc_publish` and a `data` summary with
`success`, `dry_run`, `created`, `existing`, `failed`, `planned`, `skipped` and
`items`. Items include canonical type/value, external ID, source references and
status. Successful live items include the SentinelOne `uuid`; dry-run items include
the full scoped creation payload.

Lookup/write failures set `success=false` and a top-level `error` with counts.
**Some indicators may already have been published.** API errors/warnings, malformed
responses and missing acknowledgements also fail, even on HTTP 2xx. Provider error
bodies and exception details are not returned, to avoid exposing credentials.

This blocking action stops dependent workflow execution on failure. Successful
summaries are available under
`_env.misp_module_results.sentinelone_ioc_publish`. On failure, MISP may retain
only the top-level error; standalone API clients receive the per-item summary too.

## Limits and validation

Inputs may contain at most **100 unique indicators**; larger inputs fail before
network access. Split larger jobs. Each request has a 15-second timeout, and a
240-second processing budget is checked before each indicator and again after
lookup before creation. TLS verification is enabled, redirects are disabled, and
rate limits are reported without retries. Partial remote writes are not rolled
back if another indicator fails or the caller times out.

Tests cover mocked API responses, actual `requests` serialization through mocked
HTTP transport, and the module server's discovery/query endpoints. They do not
change a live SentinelOne tenant. Validate permissions and tenant-specific behavior
in your deployment before enabling publication.

API contract: [SentinelOne Threat Intelligence reference](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/tags/Threat_Intelligence.md).
