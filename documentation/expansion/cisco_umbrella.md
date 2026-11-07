# Cisco Umbrella Investigate

`cisco_umbrella` is an expansion and hover module for fully qualified `domain`
and `hostname` attributes. It queries the current Umbrella Investigate v2 API for
domain status, security and content categories, and risk scores with contributing
features. Domain names use non-transitional IDNA2008/UTS-46 normalization through
the `idna` library; a trailing DNS dot is removed. This preserves distinct domain
identities, for example `faß.de` becomes `xn--fa-hia.de`, while `fass.de` remains
`fass.de`. Hostnames are queried exactly, without reducing them to a parent domain.

## Configuration

Enable **Cisco Umbrella Investigate** in MISP's enrichment settings and configure:

| Setting | Default | Meaning |
| --- | --- | --- |
| `api_key` | Required | The API key created in the Umbrella dashboard. |
| `api_secret` | Required | The corresponding API secret. |
| `timeout` | `20` | Connect/read timeout per HTTP request, in seconds, from 1 to 120. |

The account needs an Umbrella Investigate entitlement. Grant the API key
**`investigate.investigate:read`** permission. An API key for another Umbrella
resource does not by itself grant Investigate access. This module uses the
current key/secret OAuth flow, rather than the legacy Investigate bearer-token
API at `investigate.api.umbrella.com`.

Credentials can also be provided through the module server's
[local module configuration](https://misp.github.io/misp-modules/module-config/)
under `cisco_umbrella`. No additional Python dependency is required.

## API requests and token lifetime

The module calls these fixed HTTPS endpoints at `https://api.umbrella.com`:

1. `POST /auth/v2/token`, with HTTP Basic authentication and form data
   `grant_type=client_credentials`.
2. `GET /investigate/v2/domains/categorization/{domain}?showLabels=`, with bearer
   authentication. Category labels are requested instead of numeric IDs.
3. `GET /investigate/v2/domains/risk-score/{domain}`, with bearer authentication.

Tokens are reused in a process-local cache for the same key/secret pair until
nearly expired. The cache holds at most 32 credential identities, stored as
SHA-256 digests, alongside the bearer tokens; it does not retain the original
key or secret. The advertised lifetime is capped at one hour with an early
expiry margin of up to 60 seconds. Concurrent token requests are serialized.
API HTTP 400/401 responses invalidate the cached token for the next lookup.

A lookup makes two Investigate requests and, on a token-cache miss, one token
request. There is no pagination, automatic retry or redirect following. The
timeout applies to each request, rather than to the entire lookup. TLS
verification, the configured CA bundle and ambient proxy settings are preserved.
Explicit authentication prevents `.netrc` from replacing the bearer credentials.
Sessions and responses are closed after use. Standard module HTTP debug tracing,
if explicitly enabled on the server, includes authentication headers and bodies.

## Results and errors

The original attribute is returned unchanged, including its UUID, detection flag
and comment. A standard `annotation` object references it with `describes`.
The annotation's text attribute contains JSON with:

- `provider`, normalized `domain` and UTC `retrieved_at`;
- `categorization`: numeric `status`, `status_label`, `security_categories` and
  `content_categories`;
- `risk`: `risk_score` and the `indicator`, `normalized_score`, and raw `score`
  for each contributing feature;
- `status`: `complete` or `partial`, and `errors` identifying failed lookups.

All generated attributes use `to_ids=false` and `disable_correlation=true`.
The module creates no maliciousness tags and changes no Umbrella policy.
The categorization status is Cisco's assessment: `-1` means malicious, `0` means
unclassified and `1` means benign. Risk scores range from 0 to 100, with larger
values indicating higher risk. Zero scores and empty category lists are retained.
A benign classification or low score is provider context, not a guarantee.

If one lookup fails, the other result is retained and the report is marked
`partial`; warnings also appear in the module response. Invalid JSON, malformed
responses and missing scores are errors, never converted into zero scores or
benign classifications. Authentication failure or failure of both lookups returns
a module error. Errors include HTTP status codes without copying response bodies,
exception details, API secrets or bearer tokens.

Category lists and risk feature lists are limited to 100 entries each, with
labels up to 256 characters. Exceeding those bounds makes that lookup invalid;
results are not silently truncated. IPs, URLs, file hashes, passive DNS, WHOIS,
bulk lookups and organization policy/reporting operations are outside this
module's input and output contract.

## Example

POST to the module server's `/query` endpoint:

```json
{
  "module": "cisco_umbrella",
  "config": {
    "api_key": "YOUR_UMBRELLA_API_KEY",
    "api_secret": "YOUR_UMBRELLA_API_SECRET"
  },
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org",
    "to_ids": false
  }
}
```

## Verification and references

`tests/test_cisco_umbrella.py` exercises prepared HTTP requests with synthetic
API responses, including authentication, token expiry/isolation, normalization,
schema validation, partial failures, source preservation, PyMISP object output,
and discovery/query endpoints. No live Umbrella account was used for validation.

- [Umbrella API getting started and OAuth flow](https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/)
- [Investigate API overview](https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-investigate-api-overview/)
- [Investigate OAuth scopes](https://developer.cisco.com/docs/cloud-security/umbrella-api-oauth-scopes/)
- [Domain status and categorization](https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-investigate-investigate-api-domain-status-and-categorization-get-domain-status-and-categorization/)
- [Risk scores for domains](https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-investigate-investigate-api-security-information-for-a-domain-get-risk-score-for-domain/)
