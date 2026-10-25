# ShadowTrackr

Enrich IP addresses with ShadowTrackr false-positive and infrastructure context.

Posts JSON to /api/v3/ip_info for IPv4 or IPv6. The API key, IP and labels are sent in the JSON body, so the API key does not appear in the request URL. Existing attribute tags are sent as labels. Returns the false_positive_estimate, provider details and VPN/CDN/cloud/bogon/Tor/public-DNS flags in a referenced annotation. Scores are reported without changing MISP decay scores or IDS flags.

Input: ip-src, ip-dst. Output: A referenced annotation containing IP intelligence.

Configuration: apikey. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://shadowtrackr.com/docs_v3/5-API

Example request:

```json
{
  "module": "shadowtrackr",
  "attribute": {
    "type": "ip-dst",
    "value": "1.1.1.1",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_shadowtrackr.py` uses mocked service responses;
no paid API credentials are needed.
