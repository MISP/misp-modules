# Team Cymru Scout Search

Run an explicit Scout search query and import the returned intelligence.

The text attribute is used verbatim as Scout search syntax; no MISP or STIX pattern is inferred. Uses GET /search with query and days parameters. days defaults to 7 (1-90). STIX 2 results are converted by misp-stix, preserving relationships, source context and markings. Install the all dependency extra for misp-stix support.

Input: text. Output: MISP attributes, objects and tags converted from Scout search results.

Configuration: apikey, days. Required: apikey.
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
  "module": "team_cymru_scout_search",
  "attribute": {
    "type": "text",
    "value": "port:443",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_team_cymru_scout_search.py` uses mocked service responses;
no paid API credentials are needed.

Supported intelligence is retained if optional STIX objects cannot be converted. Partial results include an explicit notice; a bundle with no usable converted intelligence produces an error.
