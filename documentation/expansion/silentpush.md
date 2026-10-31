# Silent Push Enrichment

Retrieve domain and IP risk and infrastructure context from Silent Push.

Uses the documented enrich endpoint with x-api-key authentication. URL inputs query only the hostname. IPv4 and IPv6 use their respective endpoints. Risk scores and flags remain in a referenced annotation; AS numbers, reverse DNS and nameservers become pivotable attributes. Does not submit or scan URLs.

Input: domain, hostname, ip-src, ip-dst, url. Output: A context annotation and related ASN and hostname attributes.

Configuration: apikey. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://help.silentpush.com/docs/get-enrichment-data

Example request:

```json
{
  "module": "silentpush",
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

Validation: `pytest tests/test_silentpush.py` uses mocked service responses;
no paid API credentials are needed.

Domain, hostname and URL lookups also extract ASN and PTR pivots from all nested `ip2asn` records, deduplicating shared ASNs and hostnames.
