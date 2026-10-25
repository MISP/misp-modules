# Zetalytics Passive DNS

Look up passive DNS records in Zetalytics.

Uses the Zonecruncher v2 domain2rrtypes or ip endpoint with token authentication. max_results defaults to 25 (1-100). Returns DNS record objects for A, AAAA, CNAME, MX, NS, PTR and TXT, with first/last observation times when available. Duplicate records are suppressed and unsupported record types remain in annotations. No additional SDK is required.

Input: domain, hostname, ip-src, ip-dst. Output: Referenced DNS record objects with observation times.

Configuration: apikey, max_results. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://zonecruncher.com/
- https://github.com/ZETAlytics/community/tree/master/zetalytics-api

Example request:

```json
{
  "module": "zetalytics",
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

Validation: `pytest tests/test_zetalytics.py` uses mocked service responses;
no paid API credentials are needed.

Observation boundaries come from `first_seen` and `last_seen`. UNIX seconds and ISO 8601/date strings are accepted and normalized to UTC; timestamp zero is retained. Legacy `first_ts`/`last_ts` and the first-observation `date` field are fallback inputs. Deduplication includes the normalized observation times.
