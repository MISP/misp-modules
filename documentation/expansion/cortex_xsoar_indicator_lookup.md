# Cortex XSOAR Indicator Lookup

`cortex_xsoar_indicator_lookup` reads Cortex XSOAR 8's indicator store using
`POST /xsoar/public/v1/indicators/search`. It supports expansion and hover queries,
returning verified values with reputation, expiration and selected metadata.

## Existing Palo Alto coverage reviewed

The repository had no outbound XSOAR module before this addition. Existing
Palo Alto modules cover separate products/interfaces:

| Module | Existing capability |
| --- | --- |
| `cortex_xdr_ioc_lookup` | Read Cortex XDR IOC rules through `/public_api/v1/indicators/get`. |
| `cortex_xdr_ioc_publish` | Publish missing XDR IOC rules through `indicators/insert_jsons`. |
| `paloalto_wildfire` | Obtain WildFire verdicts/reports or submit an attachment. |
| `panos_export` | Produce PAN-OS rule configuration text. |

These do not search XSOAR indicators or create XSOAR incidents. XSOAR 8 needs
its own tenant/API key, key ID, and `/xsoar/public/v1` routes. A native MISP
integration installed *inside* XSOAR is a separate integration direction.

## Configuration

| Setting | Meaning |
| --- | --- |
| `url` | HTTPS API origin copied from XSOAR's API Keys page, e.g. `https://api-company.example`. A full root ending in `/xsoar/public/v1` is also accepted. Use the API FQDN, not the browser/UI FQDN. |
| `api_key` | XSOAR API key with permission to search indicators in the tenant. |
| `api_key_id` | Required positive numeric API key ID. |
| `auth_type` | `advanced` (default) or `standard`, matching the key created in XSOAR. |
| `limit` | Maximum candidate records requested, 1–100; default 20. |
| `timeout` | Request timeout in seconds, 1–120; default 20. |

Standard keys send the raw key in `Authorization`, without a Bearer prefix.
Advanced keys send `SHA256(key + nonce + timestamp)` in that header, plus a fresh
64-character nonce and a timestamp in milliseconds. Both modes send
`x-xdr-auth-id`. Explicit request authentication prevents `.netrc` credentials
from replacing these headers.

HTTPS verification, standard requests proxy settings and `REQUESTS_CA_BUNDLE`
are preserved. Redirects and automatic retries are disabled. Responses are limited
to 2 MiB. Credentials and backend error bodies are not returned. This module
targets XSOAR 8 APIs, rather than legacy XSOAR 6 or Cortex XDR routes.

## Request

```json
{
  "module": "cortex_xsoar_indicator_lookup",
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org"
  },
  "config": {
    "url": "https://api-company.example",
    "api_key": "YOUR_API_KEY",
    "api_key_id": "2841",
    "auth_type": "standard",
    "limit": "20"
  }
}
```

## Indicator matching

Supported MISP types are `domain`, `hostname`, `ip-src`, `ip-dst`, `md5`, `sha1`,
`sha256`, `sha512`, `url`, `email`, `email-src`, `email-dst` and `vulnerability`
(CVE identifiers). A valid UUID and non-empty UTF-8 value up to 4096 characters
are required, without control characters or surrounding whitespace.

DNS names use IDNA 2008/UTS 46 nontransitional encoding, lowercase ASCII and no
trailing root dot. IPs are canonicalized, hashes lowercased and CVEs uppercased.
URL/email values stay literal and case sensitive. Scoped IPs and CIDRs are
excluded. The original MISP attribute is preserved unchanged.

The module builds a quoted, escaped query, rather than accepting query syntax
from attribute values. A domain query is `value:"example.org" AND type:"Domain"`.
IP and IPv6 types are selected according to the address family. Domain/hostname
attributes search the standard `Domain` indicator type; custom hostname types
are not included. URLs, emails and CVEs use `URL`, `Email` and `CVE` respectively.

XSOAR merges File indicators: an MD5/SHA1 can be a property of a File whose primary
value is SHA256. Hash queries therefore search both `value` and the corresponding
`md5`/`sha1`/`sha256`/`sha512` field, restricted to `File` or the corresponding
legacy hash type. Returned matches must prove equality through the primary value
or that specific `CustomFields` hash field. Matches show `matched_fields` so that
the matching property is explicit. Unrelated custom fields are not searched as
evidence. Support for individual hash types depends on the tenant's enabled types.

## Results and limits

The API returns `iocObjects` and `total`, rather than an XDR `reply` wrapper. The
module validates identities/counts and rejects non-empty `accountErrors` because
they indicate an incomplete multi-account search. Duplicate IDs are checked per
account. Explicit zero totals with null indicator arrays are accepted as empty.

A referenced `annotation` object contains the normalized query, verified matches,
candidate/returned/discarded counts and truncation status. Selected provider
metadata includes scores, sources, timestamps, expiration, investigation IDs,
account and custom fields. False/zero values are preserved. Expired indicators
remain visible with their expiration metadata. Annotation text is non-IDS with
correlation disabled; scores are not automatically converted to MISP verdicts or
IDS attributes. A stored indicator is not proof of an endpoint detection.

Only one bounded request is made. The documented filter has `size` but no page or
cursor parameter, so the module does not invent pagination fields. When the
reported total exceeds returned candidates, it sets `truncated: true` and warns.
If there are no verified matches on an incomplete page, status is `inconclusive`.
On a complete page it is `not_found`, which is not a benign verdict. `found` can
still be truncated. Provider URLs and references are never followed.

Malformed responses, authentication/access errors, HTTP 404/429 and account
search errors produce an error, rather than a no-match result. Indicator writes,
incident synchronization and playbook execution are outside this lookup's scope.

## References

- [XSOAR 8 SaaS API setup](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/troubleshoot-and-reference/reference/cortex-xsoar-api)
- [Standard and Advanced authentication](https://cortex-docs.paloaltonetworks.com/xsoar-8-api/make-your-first-api-call)
- [Current indicator API schemas](https://cortex-docs.paloaltonetworks.com/xsoar-8-api/cortex-xsoar-8.x-apis/indicators)
- [Merged File indicators](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/investigate-and-respond-to-threats/threat-intel-management/indicator-configuration/customize-indicator-types-fields-and-layouts/file-indicators)
