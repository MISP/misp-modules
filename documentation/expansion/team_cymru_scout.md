# Team Cymru Scout

Retrieve Scout foundation intelligence for an IP address or search for a domain.

Uses Bearer authentication against /ip/foundation?ips= for IPv4/IPv6 or /search?query= for domains. Returned STIX 2 bundles are converted using misp-stix, preserving relationships, source context and markings. No data is submitted to an analysis queue. Install the all dependency extra for misp-stix support.

Input: domain, hostname, ip-src, ip-dst. Output: MISP attributes, objects and tags converted from Scout STIX intelligence.

Configuration: apikey. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://scout.cymru.com/

Example request:

```json
{
  "module": "team_cymru_scout",
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

Validation: `pytest tests/test_team_cymru_scout.py` uses mocked service responses;
no paid API credentials are needed.

Supported intelligence is retained if optional STIX objects cannot be converted. Partial results include an explicit notice; a bundle with no usable converted intelligence produces an error.
