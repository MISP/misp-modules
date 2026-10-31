# Metras Enrichment

Enrich file hashes and IP addresses with Metras EDR inventory and fleet context.

url defaults to https://api.metras.sa/api. Uses X-API-KEY authentication. Hash lookups query binary details (MD5) or binary inventory (SHA-1/SHA-256). IP lookups query EDR alerts and endpoint inventory. max_results defaults to 25 (1-100). Results retain binary metadata, alert context and fleet hostnames; additional pages are reported as truncated.

Input: md5, sha1, sha256, ip-src, ip-dst.

Configuration: apikey, url, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://metras.sa/

Example request:

```json
{
  "module": "metras",
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

Validation: `pytest tests/test_metras.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.
