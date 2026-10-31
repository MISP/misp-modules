# OSINT Industries

Find OSINT Industries account and identity context for an email, phone, username or wallet.

Uses POST /v2/request with api-key header authentication, exact_match=true and premium lookups disabled. Username attributes query the username selector; BTC addresses query wallet. max_results defaults to 25 (1-100). Module-level results retain provenance in annotations; registered accounts become user-account objects and valid profile URLs become links. Lookups can consume API credits.

Input: email-src, email-dst, phone-number, github-username, btc.

Configuration: apikey, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.osint.industries/

Example request:

```json
{
  "module": "osint_industries",
  "attribute": {
    "type": "email-src",
    "value": "test@example.com",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_osint_industries.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

The provider lookup timeout is 25 seconds, the documented minimum, and the HTTP timeout is 30 seconds. Results support typed `spec_format` arrays, legacy mappings, and normalized `data` objects; normalized values take precedence when both forms are supplied.
