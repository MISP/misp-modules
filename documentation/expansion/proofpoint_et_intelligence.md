# Proofpoint ET Intelligence

Enrich domains, IPv4 addresses and MD5 hashes using Proofpoint ET Intelligence.

Uses the v1 API with Authorization header authentication. IP and domain queries return reputation plus passive DNS pivots; MD5 queries return sample details. IPv6 is rejected before querying because the service contract is IPv4. max_results defaults to 25 (1-100). Reputation scores are retained as context, including score zero, and do not change source IDS flags.

Input: domain, hostname, ip-src, ip-dst, md5.

Configuration: apikey, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://eti.emergingthreats.net/

Example request:

```json
{
  "module": "proofpoint_et_intelligence",
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

Validation: `pytest tests/test_proofpoint_et_intelligence.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

Sample `file_size` is mapped to the file object `size-in-bytes` relation, including zero-byte files.
