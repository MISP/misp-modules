# Shodan InternetDB

Look up exposed services, hostnames, CPEs and vulnerabilities in the free Shodan InternetDB API.

No API key is required. Supports IPv4 and IPv6. A 404 means no information is available. Hostnames and vulnerabilities are pivotable attributes; ports are grouped in an ip-port object. Service tags are retained as context, without automatically tagging the source as malicious.

Input: ip-src, ip-dst. Output: An ip-port object and hostname, CPE and vulnerability attributes.

Configuration: none. Required: none.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://internetdb.shodan.io/

Example request:

```json
{
  "module": "shodan_internetdb",
  "attribute": {
    "type": "ip-dst",
    "value": "1.1.1.1",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {}
}
```

Validation: `pytest tests/test_shodan_internetdb.py` uses mocked service responses;
no paid API credentials are needed.
