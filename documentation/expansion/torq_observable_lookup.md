# Torq Observable Lookup

`torq_observable_lookup` is an expansion and hover module for retrieving Torq
observable reputation, enrichment and threat intelligence. It uses the read-only
[`POST /v1alpha/observables/query`](https://developers.torq.io/apidocs/query-observables)
API, with local value checks because the API's `search` filter is broader than
an equality lookup.

## Configuration

Torq API keys belong to a specific workspace. Use credentials created in the
workspace whose observables you want to query, with permission to read them.

| Setting | Meaning |
| --- | --- |
| `region` | `us` (default), `eu` or `jp`. Selects the documented regional API base, including `/public`. |
| `client_id`, `client_secret` | API key pair for automatic OAuth client-credentials exchange in US/EU. |
| `access_token` | Alternatively, an existing Torq bearer token. Do not configure it together with the client credential pair. |
| `limit` | Candidate page size, 1–100; default 20. |
| `timeout` | Timeout per request, 1–120 seconds; default 20. |

| Region | API base | Automatic token endpoint |
| --- | --- | --- |
| `us` | `https://api.torq.io/public` | `https://auth.torq.io/v1/auth/token` |
| `eu` | `https://api.eu.torq.io/public` | `https://auth.eu.torq.io/v1/auth/token` |
| `jp` | `https://api.jp.torq.io/public` | Supply an existing `access_token`. |

The current authentication guide documents token endpoints for US/EU. The module
supports JP's documented API base with a supplied bearer token, without assuming
a JP token endpoint. Torq tokens normally expire after one hour; supplied tokens
must be renewed by the operator. Client-credentials mode requests a fresh token
for each invocation using HTTP Basic authentication and form field
`grant_type=client_credentials`. Tokens are not cached between requests.

Credentials and tokens are never included in results or errors. HTTPS validation,
standard requests proxy settings and `REQUESTS_CA_BUNDLE` are preserved.
Redirects and automatic retries are disabled. Each response is limited to 2 MiB.
The module only contacts the fixed regional authentication/API endpoints.

## Request

```json
{
  "module": "torq_observable_lookup",
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org"
  },
  "config": {
    "region": "us",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "limit": "20"
  }
}
```

Supported MISP types and Torq fields:

| MISP type | Torq type / value field |
| --- | --- |
| `domain`, `hostname` | `TYPE_ID_HOSTNAME` / `hostname` |
| `ip-src`, `ip-dst` | `TYPE_ID_IP_ADDRESS` / `ip` |
| `md5`, `sha1`, `sha256` | `TYPE_ID_FILE_HASH` / `file_hash` |
| `email`, `email-src`, `email-dst` | `TYPE_ID_EMAIL_ADDRESS` / `email_address` |
| `url` | `TYPE_ID_URL` / `url` |
| `filename` | `TYPE_ID_FILE_NAME` / `file_name` |

Input must have a valid UUID and non-empty UTF-8 value of at most 4096 characters,
without surrounding whitespace. Hashes must have the expected hexadecimal length;
IPs must be individual addresses without a CIDR suffix or zone identifier. DNS
hostnames use IDNA 2008/UTS 46 nontransitional encoding and lowercase ASCII, with a
trailing root dot removed. Hashes are lowercased and IPs canonicalized. URLs,
emails and filenames use literal, case-sensitive values. SHA512 and composite
attributes are not supported. The original MISP attribute is preserved unchanged.

## Matching and completeness

The request contains `filter.types: [{"id": "TYPE_ID_..."}]`, `filter.search`
with the normalized value, `page_size`, and descending `last_seen` ordering.
Only one bounded candidate page is requested. Returned observable IDs, types and
typed value fields are validated; only active values matching the normalized
query are retained. Broader matches such as `sub.example.org` for `example.org`
are discarded. Hash subtype filters are not required, so legacy observables with
an unknown subtype remain searchable.

The module attaches a referenced `annotation` object with a JSON report containing
the query, region, type, verified `matches`, candidate/returned/discarded counts
and `truncated` flag. Provider reputation, timestamps, case counts, enrichment and
threat intelligence are retained, including false and zero values. The annotation
is non-IDS with correlation disabled. URLs inside provider data are never fetched.

- `found`: at least one verified active match was returned. `truncated` can still
  be true, so this does not promise that all matches were retrieved.
- `not_found`: the completed candidate page contained no verified active match.
  This is not a benign verdict or a claim about every spelling of an observable.
- `inconclusive`: no verified match was returned, but `next_page_token` indicates
  more candidates. Later pages could contain exact matches.

A non-empty `next_page_token` produces a warning; it is not followed. Missing
observable lists, malformed pages, authentication failures, access errors, HTTP
404/429 and other request errors are never represented as a no-match result.
Torq documents a limit of 50 API requests per second; configure workflow/hover
usage to fit the workspace's overall request rate.

## References

- [Overview, regions and rate limits](https://developers.torq.io/apidocs/overview)
- [Authentication](https://developers.torq.io/apidocs/authentication)
- [Observable query schema and pagination](https://developers.torq.io/apidocs/query-observables)
