# Cisco PSIRT openVuln

`cisco_psirt` is an expansion and hover module for Cisco security advisories. It
uses the current openVuln v2 API and the OAuth flow documented by Cisco PSIRT.

## Inputs

| Attribute type | Value | Lookup |
| --- | --- | --- |
| `vulnerability` | `CVE-2022-20714` | Advisories associated with a CVE. |
| `text` | `CVE-2022-20714` | The same CVE lookup. |
| `text` | `cisco-sa-lsplus-Z6AQEOjk` | A particular Cisco advisory. |
| `text` | `CSCvy48962` | Advisories associated with a Cisco bug. |

An attribute UUID is required so results can reference the source. Leading and
trailing whitespace is removed for the lookup. CVEs normalize to uppercase;
bug IDs normalize to `CSC` plus two lowercase letters and five digits. Advisory
ID case is preserved, including its suffix. Arbitrary text, URLs, product names,
CPEs and software-version strings are not accepted by this module.

The bug-ID endpoint can return partial matches according to Cisco's reference.
The module retains only advisories whose `bugIDs` include the exact normalized
query. Discarded partial matches are counted. CVE and advisory-ID responses are
checked against the requested identifier; mismatches return an error.

## Configuration

Enable **Cisco PSIRT** in MISP's enrichment settings and configure:

| Setting | Default | Meaning |
| --- | --- | --- |
| `client_id` | Required | The key for an application registered in Cisco API Console. |
| `client_secret` | Required | The corresponding client secret. |
| `max_advisories` | `20` | Maximum number of matching advisories to import, from 1 to 100. |
| `timeout` | `20` | Connect/read timeout per HTTP request, in seconds, from 1 to 120. |

Register a service application with the Client Credentials grant and enable the
**Cisco PSIRT openVuln API** for that application, following Cisco's authentication
guide. Credentials for Cisco Umbrella are separate from this API registration.
The module uses the existing `requests`, Beautiful Soup and PyMISP dependencies;
no additional installation is needed.

For local server defaults, use `cisco_psirt` in the
[module configuration file](https://misp.github.io/misp-modules/module-config/).

## Results

The original attribute is returned unchanged, including its UUID, detection flag
and comment. Each imported advisory produces:

- A standard `vulnerability` object with its Cisco advisory ID and associated
  CVEs in `id`, title in `summary`, plain-text advisory summary in `description`,
  CVSS base score, publication/update dates, publication status and references.
  References include the advisory page and CSAF document URL when supplied.
  Optional URLs containing `NA` or `N/A` are treated as missing, including
  surrounding whitespace and case variants; malformed non-placeholder URLs
  still return an error.
- A linked standard `annotation` containing the normalized advisory fields,
  including Cisco bug IDs, CWEs, product names, IPS signatures, severity (`sir`),
  advisory version and the other mapped values. It references both the source
  attribute and the vulnerability object.

All generated attributes use `to_ids=false`. Annotation text also disables
correlation. The original attribute's detection setting is preserved. Scores
belong to the advisory as a whole and are not individual CVE assessments.
HTML summaries become plain text, excluding script and style contents. Dates
are normalized to UTC; timezone-free dates from Cisco are interpreted as UTC,
as specified in its introduction. Zero CVSS scores are retained, while missing
scores and `NA`/`N/A` placeholders do not become zero scores.

Product names and CWEs remain advisory context. Product names are not converted
to CPEs or interpreted as proof that a particular installed release is affected.
The module retains CSAF links but does not fetch CSAF or legacy CVRF documents.
Software Checker, product/version searches, bulk feeds and time-range queries
are outside this module's input contract.

A final annotation, also exposed as the response's `summary`, records the query,
retrieval time, provider row count, imported count, discarded partial bug matches,
and truncation flag. When `max_advisories` is reached, a warning explains the
local limit. No additional pages are requested.

Empty advisory arrays and the documented HTTP 404 codes `NO_DATA_FOUND` and
`ADVISORYID_NOT_FOUND` produce `status: not_found` with the source and summary
annotation. This means no matching Cisco advisory was returned, not that a
product is free of vulnerabilities. Other errors, malformed fields and unexpected
404 codes return module errors without partial objects.

## HTTP behavior

The module obtains a bearer token from
`https://id.cisco.com/oauth2/default/v1/token`, sending `client_id`, `client_secret`
and `grant_type=client_credentials` as form data. It queries the appropriate
`/cve/{id}`, `/advisory/{id}` or `/bugid/{id}` endpoint under
`https://apix.cisco.com/security/advisories/v2`, with `summaryDetails=true` and
`productNames=true`. Credentials and tokens are not sent in URLs.

Tokens are reused in a bounded process-local cache isolated by the credential
pair, with up to 32 SHA-256 credential identities and bearer tokens. Raw client
credentials are not retained in the cache. Token lifetime is capped at one hour
with an early-expiry margin of up to 60 seconds. Concurrent token issuance is
serialized. An API HTTP 401 evicts that token for the next lookup; HTTP 429 does
not force token refresh.

A lookup makes one advisory request and, on a cache miss, one token request.
Requests preserve TLS verification, CA bundle and proxy settings; explicit auth
prevents `.netrc` from replacing the OAuth credentials. Redirects and automatic
retries are disabled. Timeouts apply to individual requests rather than to the
entire lookup. Decoded response bodies are capped at 2 MiB, and responses and
sessions are closed after use. Error messages omit provider response bodies and
credential-bearing exception details. The server's opt-in HTTP debug tracing
logs headers and bodies, including credentials.

## Example

POST to the module server's `/query` endpoint:

```json
{
  "module": "cisco_psirt",
  "config": {
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET"
  },
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "vulnerability",
    "value": "CVE-2022-20714",
    "to_ids": false
  }
}
```

## Verification and references

`tests/test_cisco_psirt.py` uses synthetic responses while exercising requests'
real form encoding and authentication preparation. It covers identifier routing,
object mapping, exact-match filtering, empty results, limits, error handling,
token expiry/isolation, HTML handling and discovery/query endpoints. No live
PSIRT credentials were available for validation.

- [PSIRT introduction](https://developer.cisco.com/docs/psirt/introduction/)
- [Application registration and authentication](https://developer.cisco.com/docs/psirt/authentication/)
- [Queries by identifiers](https://developer.cisco.com/docs/psirt/obtain-advisory-by-identifiers/)
- [CVE endpoint](https://developer.cisco.com/docs/psirt/cvecve_id/)
- [Advisory endpoint](https://developer.cisco.com/docs/psirt/advisoryadvisoryid/)
- [Bug-ID endpoint and partial-match behavior](https://developer.cisco.com/docs/psirt/bugidbug_id/)
