# Tines Record Lookup

`tines_record_lookup` is an expansion and hover module for finding an observable
in a selected Tines record type. It uses the read-only
[`POST /api/v2/records/search`](https://www.tines.com/stories/docs/api/records/search/)
endpoint recommended for new integrations.

## Configuration

| Setting | Meaning |
| --- | --- |
| `url` | HTTPS tenant origin, for example `https://example.tines.com`. Custom domains and self-hosted origins are supported; omit paths. |
| `api_key` | Tines API key with access to the selected record type. Sent in `X-User-Token`. |
| `record_type_id` | Required positive numeric record type ID. |
| `field_id` | Required positive numeric field ID on that record type, obtained from Tines record type/field configuration or APIs. |
| `limit` | Maximum records returned in one request, 1–100; default 20. |
| `test_mode` | Search test records when true; default false (live records). |
| `timeout` | Request timeout in seconds, 1–120; default 20. |

Use an API key with the smallest suitable scope. A key without sufficient access
can receive HTTP 404; this is an error, never an empty search result. API keys are
not included in output. HTTPS certificate validation, standard requests proxy
settings and `REQUESTS_CA_BUNDLE` are preserved. Redirects are refused.

The selected field must support `EQUAL` for the supplied value. Tines supports
this operator for text, enum, regex, email, URL, IP address, number and timestamp
fields, rather than JSON/artifact or boolean fields. Field IDs remain stable
when a field is renamed. The source value is passed literally as a JSON filter
value, without a query language, hash lowercasing, IP normalization or IDNA
conversion; matching follows Tines' field semantics.

## Request

```json
{
  "module": "tines_record_lookup",
  "attribute": {
    "type": "domain",
    "value": "example.org",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "url": "https://example.tines.com",
    "api_key": "YOUR_API_KEY",
    "record_type_id": "42",
    "field_id": "101",
    "limit": "20",
    "test_mode": "false"
  }
}
```

Supported attribute types are `text`, `md5`, `sha1`, `sha256`, `sha512`, `domain`,
`hostname`, `ip-src`, `ip-dst`, `url`, `email`, `email-src`, `email-dst` and
`vulnerability`. A valid UUID and non-empty string up to 4096 characters are
required. The observable is sent to the configured Tines tenant.

## Results and limits

The original attribute is preserved. A referenced `annotation` object contains a
JSON report with the source query, record type/field IDs, test mode, matching
records, field ID map, returned/total counts and `truncated` flag. Its text is
non-IDS with correlation disabled. Provider fields, including false values and
artifact handles, are retained as evidence; they are not converted into IDS
indicators. Review returned data before sharing it with other MISP communities.

Only one bounded result page is requested. A v2 `page.next_page_token` or a total
larger than the returned count produces a warning and `truncated: true`.
Pagination cursors and artifact URLs are never followed. Responses exceeding
2 MiB, malformed replies, mismatched record types/filters and HTTP errors are
reported as errors. There are no automatic retries.

`not_found` means no records matched in the configured type, field and live/test
scope; it is not a benign verdict. HTTP 404, access errors and malformed/incomplete
responses are not represented as `not_found`.

## References

- [API welcome and versioning](https://www.tines.com/stories/docs/api/welcome/)
- [Authentication and key scopes](https://www.tines.com/stories/docs/api/authentication/)
- [Records v2 search and filters](https://www.tines.com/stories/docs/api/records/search/)
- [Stories OpenAPI specification](https://www.tines.com/stories/docs/api/openapi.json)
