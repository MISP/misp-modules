# Cortex XDR IOC Lookup

`cortex_xdr_ioc_lookup` is an expansion/hover module that looks for a supplied
observable in a tenant's configured Cortex XDR IOC rules. It uses the public
`POST /public_api/v1/indicators/get` API with exact indicator and type filters.
It does not search endpoint telemetry, alerts or incidents. A matching rule
does not establish that an endpoint encountered the observable, and an empty
lookup is not a benign verdict.

## Existing Palo Alto coverage

| Module | Purpose | Relationship to Cortex XDR |
| --- | --- | --- |
| `paloalto_wildfire` | Retrieve verdicts/reports or submit an attachment to WildFire. | Uses the separate WildFire public API and its API key. |
| `panos_export` | Render PAN-OS security-rule configuration from MISP indicators. | Produces configuration text; it does not call an XDR tenant. |
| `cortex_xdr_ioc_lookup` | Retrieve exact IOC-rule matches from an XDR tenant. | Adds authenticated XDR IOC API coverage. |

The [API Security page](https://cortex-docs.paloaltonetworks.com/cortex-xdr/configure-cortex-xdr/cortex-xdr-data-sources/vendor-specific-data-sources/api-security)
describes collection of API traffic from AWS, Azure, F5, Apigee and Kong gateways.
Those ingestion connectors are separate from this IOC lookup API. WildFire keys,
PAN-OS configuration exports, Cortex XSOAR integrations and XDR API keys are
separate interfaces and are not interchangeable.

## Configuration

Enable **Cortex XDR IOC Lookup** in MISP's enrichment settings.

| Setting | Default | Meaning |
| --- | --- | --- |
| `url` | Required | Tenant API HTTPS origin copied from XDR API Keys, such as `https://api-tenant.example`. No endpoint path, credentials, query or fragment. |
| `api_key` | Required | API key value from the XDR tenant. |
| `api_key_id` | Required | Matching key ID as a string of digits. |
| `auth_type` | `advanced` | `standard` sends the key directly; `advanced` signs each request. Must match the key's security level. |
| `limit` | `20` | Maximum matching records requested, from 1 to 100. |
| `timeout` | `20` | Connect/read timeout per request, from 1 to 120 seconds. |

Palo Alto's IOC reference requires **Rules Edit** permission even for this lookup
endpoint. Configure the key and license accordingly; the module itself performs
only a lookup and makes no rule changes. No additional Python dependency or
MISP object template is needed. Local module-server defaults can be configured
under `cortex_xdr_ioc_lookup` in the server's module configuration file.

## Supported values

| MISP type | XDR type | Normalization |
| --- | --- | --- |
| `md5`, `sha256` | `hash` | Check hexadecimal length and lowercase. |
| `domain`, `hostname` | `domain_name` | Non-transitional IDNA2008/UTS-46 processing; remove the DNS root dot. `faß.de` stays distinct from `fass.de`. |
| `ip-src`, `ip-dst` | `ip` | Validate/canonicalize IPv4 or IPv6. |

An attribute UUID is required. CIDRs, scoped IPv6, port-qualified composites,
URLs, filenames, SHA-1 hashes and other composites are unsupported. Restrictions are not
dropped to broaden a lookup. The original attribute is returned unchanged.

## Authentication and response handling

Standard authentication uses `Authorization: <key>` and `x-xdr-auth-id: <id>`.
Advanced authentication adds a fresh 64-character nonce and millisecond UTC
timestamp and sends SHA-256 of `key + nonce + timestamp` as `Authorization`.
There is no OAuth token exchange. Explicit auth prevents `.netrc` from replacing
the XDR headers. Both modes preserve inherited proxy settings and CA trust.

The module verifies TLS, rejects redirects, limits decoded response bodies to
2 MiB, closes sessions/responses and performs no automatic retries. Errors omit
credentials, provider error bodies and credential-bearing exception text.
The server's opt-in HTTP debug mode logs headers and bodies, including keys.

The API's documented flat response and its `reply` envelope form are supported.
The module checks record counts, positive rule IDs, and the canonical type/value
of every returned record. Unexpected, mismatched or incomplete responses return
errors instead of empty results.

## MISP output

A standard `annotation` object references the original attribute with `describes`.
Its text is JSON containing the canonical query, `found`/`not_found` status,
returned count, `objects_count`, `truncated`, and matching rule context. Context
includes rule ID, indicator/type, severity, expiry, comment, reputation and
reliability when supplied. Other response fields are not copied. The report
preserves the native `expiration_date: -1` sentinel for non-expiring rules.
Other negative expiry values are rejected. New attributes
use `to_ids=false` and `disable_correlation=true`; no verdict tags are inferred.

The lookup requests one bounded result window. If the provider reports more
records or the result fills the requested window, `truncated=true` and a warning
indicate that completeness is not established. No additional pages are fetched.

Example request to `/query`:

```json
{
  "module": "cortex_xdr_ioc_lookup",
  "config": {
    "url": "https://api-tenant.example",
    "api_key": "YOUR_API_KEY",
    "api_key_id": "17",
    "auth_type": "advanced"
  },
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org"
  }
}
```

## Validation and references

Tests use prepared requests with synthetic API replies. They exercise both auth
modes, normalization, malformed/mismatched responses, empty results, limits,
resource cleanup, PyMISP output and discovery/query endpoints. No live XDR tenant
was available for authenticated validation.

- [Authentication](https://cortex-docs.paloaltonetworks.com/xdr-api/make-your-first-api-call)
- [IOCs and permission requirements](https://cortex-docs.paloaltonetworks.com/xdr-api/cortex-platform/iocs)
- [Copy the API origin](https://cortex-docs.paloaltonetworks.com/xdr-api/get-your-fqdn)

- [Native IOC types and Pro license](https://cortex-docs.paloaltonetworks.com/cortex-xdr/detect-investigate-and-respond-to-threats/threat-management/detection-rules/whats-an-ioc/create-an-ioc-rule)
