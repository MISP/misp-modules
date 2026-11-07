# Shuffle Datastore Lookup

`shuffle_datastore_lookup` is an expansion and hover module that reads an
enrichment record stored by a Shuffle workflow under an observable's key. It uses
the documented read-only `POST /api/v1/orgs/<org_id>/get_cache` endpoint. It does
not execute a workflow, list other keys or modify records.

## Configuration

| Setting | Meaning |
| --- | --- |
| `url` | Required HTTPS API root ending in `/api/v1`, e.g. `https://uk.shuffler.io/api/v1`. Self-hosted hosts, ports and deployment subpaths are supported. |
| `api_key` | Shuffle API key from the account's settings, with read access to the organization, category and record. Sent as `Authorization: Bearer <key>`. |
| `org_id` | Required organization UUID. Sent in the endpoint path, JSON body and `Org-Id` header. |
| `category` | Exact Datastore category, up to 128 characters; default empty (uncategorized/default). `default` is treated as the empty category. |
| `key_prefix` | Optional literal prefix, up to 128 characters; default empty. The lookup key is the prefix plus the source attribute value. |
| `timeout` | Request timeout, 1–120 seconds; default 20. |

Use the API root for your account's region. Shuffle documents UK, Frankfurt,
California and Canada hosts, as well as an Australia test region. Check the
account's current location rather than relying on a redirect from another region.
The same API supports self-hosted installations.

URLs must use HTTPS and cannot include embedded credentials, queries or fragments.
Standard requests proxy settings, certificate verification and
`REQUESTS_CA_BUNDLE` are preserved. Redirects and automatic retries are disabled.
Responses are limited to 2 MiB. The module does not use an execution authorization
or public Datastore authorization token to bypass normal API-key access.

## Request

```json
{
  "module": "shuffle_datastore_lookup",
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org"
  },
  "config": {
    "url": "https://uk.shuffler.io/api/v1",
    "api_key": "YOUR_API_KEY",
    "org_id": "2e7b6a08-b63b-4fc2-bd70-718091509db1",
    "category": "misp_intel",
    "key_prefix": ""
  }
}
```

Supported attribute types: `text`, `md5`, `sha1`, `sha256`, `sha512`, `domain`,
`hostname`, `ip-src`, `ip-dst`, `url`, `email`, `email-src`, `email-dst`,
`vulnerability` and `filename`. A valid UUID and non-empty string are required.
The complete key must fit within 1024 UTF-8 bytes and have no control characters
or surrounding whitespace. Values are passed literally as JSON, without hash
lowercasing, IP normalization or IDNA conversion. Configure keys consistently
with the Shuffle workflow that writes them.

## Identity checks and results

The request body is:

```json
{"org_id":"2e7b6a08-b63b-4fc2-bd70-718091509db1","key":"example.org","category":"misp_intel"}
```

HTTP 200 and boolean `success: true` are required. The module also verifies the
returned key and category. Shuffle can fall back to similarly named keys, even
outside the requested category; a mismatched response produces an error. If an
older version echoes the organization ID, it must match. Current versions clear
that field, so empty or absent response organization IDs are accepted after the
request explicitly selects the organization in all three documented locations.

The original MISP attribute is preserved. A referenced `annotation` object holds
a JSON report with the organization, category, key, `status: found`, raw `value`
and selected metadata (`created`, `edited`, `changed`, `encrypted`, `revision_id`
and `workflow_id`, when supplied). Annotation text is non-IDS with correlation
disabled. False, zero, null and empty values are preserved. JSON encoded inside
a string stays a string; the module does not guess how to decode or interpret it.
Provider URLs are not followed.

Top-level `authorization`, `public_authorization`, execution IDs and other
unselected API metadata are omitted. The record's `value` is returned as evidence;
it is not automatically turned into an IDS indicator or a verdict.

## Missing records and errors

Shuffle can use the same error for a missing key and failed authentication, and
Datastore read restrictions can return HTTP 404. These cannot safely be
distinguished as a no-match result. Missing/inaccessible keys, `success: false`,
HTTP errors, malformed replies, mismatched identities and timeouts all return
an error. The module never translates these into `not_found` or a benign verdict.

## References

- [Shuffle API documentation](https://shuffler.io/docs/API)
- [Official API documentation source: Datastore](https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md#datastore-api)
- [Official Datastore implementation](https://github.com/Shuffle/shuffle-shared/blob/main/datastore.go)
