# PolySwarm Enrichment

Retrieve PolySwarm sample reputation, engine verdicts and file metadata.

Queries the v3 search/hash endpoint using the Authorization header. community defaults to default; max_results defaults to 25 (1-100). Validates the requested hash against each result, returns file objects and full scan context, and reports truncation. PolyScore zero and benign engine results are retained. No samples are uploaded or rescanned.

Input: md5, sha1, sha256.

Configuration: apikey, community, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.polyswarm.io/

Example request:

```json
{
  "module": "polyswarm",
  "attribute": {
    "type": "sha256",
    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_polyswarm.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.
