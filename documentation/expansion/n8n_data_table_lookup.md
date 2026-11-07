# n8n Data Table Lookup

`n8n_data_table_lookup` is an expansion and hover module for finding a MISP
observable in a selected string column of an n8n Data Table. Use it for IOC lists,
triage results or enrichment data maintained by your n8n workflows. It uses only
the documented [public Data Table API](https://docs.n8n.io/connect/n8n-api/data-table)
and does not start or modify workflows.

## Requirements and configuration

Use an n8n version exposing the public Data Table column and row endpoints.
The public API is available on paid n8n Cloud plans and self-hosted editions,
rather than the Cloud free trial. Older versions without these endpoints return
an error. Create a key under **Settings → n8n API** and grant access to the table's
project. On Enterprise, the minimum API scopes are `dataTableColumn:read` and
`dataTableRow:read`; the account/project permissions must also allow reading the
table columns and rows. Non-Enterprise keys have the account's full API access.

| Setting | Meaning |
| --- | --- |
| `url` | Full HTTPS public API root ending in `/api/v1`, e.g. `https://example.app.n8n.cloud/api/v1`. Self-hosted subpaths such as `https://n8n.example/automation/api/v1` are supported. |
| `api_key` | Required n8n API key, sent in `X-N8N-API-KEY`. This is separate from Webhook Header Auth credentials. |
| `data_table_id` | Required 16-character alphanumeric table ID from n8n. |
| `column` | Required user-defined string column name, e.g. `indicator`. Names follow n8n's letter-first, letters/digits/underscore format, up to 63 characters. System columns are excluded. |
| `limit` | One-page row limit, 1–100; default 20. |
| `timeout` | Timeout in seconds per request, 1–120; default 20. |

URLs cannot contain embedded credentials, query strings or fragments. API keys
are not included in output. HTTPS verification, standard requests proxy settings
and `REQUESTS_CA_BUNDLE` are preserved. Redirects and automatic retries are disabled.

## Request

```json
{
  "module": "n8n_data_table_lookup",
  "attribute": {
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "type": "domain",
    "value": "example.org"
  },
  "config": {
    "url": "https://example.app.n8n.cloud/api/v1",
    "api_key": "YOUR_API_KEY",
    "data_table_id": "AbCdEfGh12345678",
    "column": "indicator",
    "limit": "20"
  }
}
```

Supported input types: `text`, `md5`, `sha1`, `sha256`, `sha512`, `domain`,
`hostname`, `ip-src`, `ip-dst`, `url`, `email`, `email-src`, `email-dst`, and
`vulnerability`. A valid UUID and non-empty UTF-8 string up to 4096 characters are
required. The observable is sent to the configured tenant in a URL-encoded query
parameter and may appear in its access logs.

## API behavior and output

Each invocation performs at most two read-only requests:

1. `GET /api/v1/data-tables/<id>/columns`: validates that the selected column
   exists exactly once, belongs to the requested table, and has type `string`.
2. `GET /api/v1/data-tables/<id>/rows`: sends `limit`, `sortBy=id:asc`, and a
   JSON-encoded filter of this shape:

```json
{"type":"and","filters":[{"columnName":"indicator","condition":"eq","value":"example.org"}]}
```

Values are passed literally without query-language interpolation, lowercasing,
IP normalization or IDNA conversion. The module expects exact string matches
and checks returned row values accordingly. Boolean, number and date lookup
columns are excluded to avoid implicit conversions; other returned columns can
retain these native types, including false, zero and null.

The original attribute is preserved. A referenced `annotation` object contains a
JSON report with the query, table ID, column, matched rows, `returned` count and
`truncated` flag. Annotation text is non-IDS with correlation disabled; returned
row contents are evidence, rather than automatically promoted IDS indicators.
The API does not return an overall match total, so the module does not invent one.

Only the first page is retrieved. A non-null `nextCursor` produces a warning and
`truncated: true`; cursors and URLs in provider data are never followed. API
responses are limited to 2 MiB per request. Invalid columns, non-matching or
duplicate rows, malformed pages, timeouts and HTTP errors produce an error.

`not_found` means that no row matched this exact column and value, rather than a
benign verdict. A missing/inaccessible table, unsupported API endpoint, HTTP 404
or any other request error is never converted into a no-match result.

## References

- [Public API overview](https://docs.n8n.io/connect/n8n-api)
- [Authentication and scopes](https://docs.n8n.io/connect/n8n-api/authentication)
- [Data Table endpoint schemas](https://docs.n8n.io/connect/n8n-api/data-table)
- [Pagination](https://docs.n8n.io/connect/n8n-api/pagination)
- [Official filter schema](https://github.com/n8n-io/n8n/blob/master/packages/%40n8n/api-types/src/schemas/data-table-filter.schema.ts)
