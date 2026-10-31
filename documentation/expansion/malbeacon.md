# MalBeacon

Retrieve MalBeacon C2 and actor infrastructure observations.

Uses GET /v1/c2/c2/{value} with X-Api-Key authentication. max_results defaults to 25 (1-100). Beacon records retain timestamps, provider context, tags and user agents in referenced annotations; actor IPs, hostnames and C2 domains become pivotable attributes.

Input: domain, hostname, ip-src, ip-dst.

Configuration: apikey, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://malbeacon.com/

Example request:

```json
{
  "module": "malbeacon",
  "attribute": {
    "type": "domain",
    "value": "example.com",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_malbeacon.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

IP literals in `c2domain`, including IPv6 addresses, become `ip-dst` pivots. Actual names become `domain` pivots.
