# MWDB Query

Query an existing file in [MWDB Core](https://github.com/CERT-Polska/mwdb-core)
using an MD5, SHA-1, SHA-256 or SHA-512 MISP attribute. The existing `mwdb`
(MWDB Submit) module handles sample uploads; `mwdb_query` only reads metadata.

Configure these settings for `mwdb_query` in MISP:

| Setting | Required | Meaning |
| --- | --- | --- |
| `mwdb_apikey` | Yes | MWDB API key with access to the files being queried. |
| `mwdb_url` | Yes | API base URL, for example `https://mwdb.cert.pl/api/`. |

These names match MWDB Submit, but each module has its own configuration.
The trailing slash is optional. Deployment prefixes such as
`https://example.org/mwdb/api/` are preserved in both API and sample links.
HTTP is supported for local deployments; use HTTPS to protect the API key in transit.
TLS certificates are verified, requests time out after 30 seconds, and redirects
are rejected. Authentication uses `Authorization: Bearer <mwdb_apikey>`.

The module calls `GET /api/file/{hash}` once. It returns a MISP file object
containing available hashes, filename and size, a link to the MWDB sample page,
and an annotation with MWDB tags, the libmagic file type and upload time.
The response must identify the queried hash and a consistent SHA-256 identifier.
MWDB tags are recorded as context, without applying them as MISP tags.
Libmagic descriptions remain in the annotation rather than being treated as MIME types.
Samples, related files and extracted configurations are not downloaded.

The source attribute retains its UUID and metadata. Returned objects reference
the source attribute, and all new attributes have `to_ids=false`.
A 404 returns only the source attribute: MWDB may return this status for either
a missing file or one the API key cannot access. Authentication, permission,
rate limit, transport and malformed response errors are reported without
including API keys or response bodies. Rate limits are not retried.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "mwdb_query",
  "attribute": {
    "type": "sha256",
    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "mwdb_apikey": "YOUR_API_KEY",
    "mwdb_url": "https://mwdb.cert.pl/api/"
  }
}
```

Validation: `pytest tests/test_mwdb_query.py` uses mocked responses and needs no
MWDB credentials.

References:

- https://mwdb.readthedocs.io/
- https://github.com/CERT-Polska/mwdb-core/blob/master/mwdb/schema/file.py
