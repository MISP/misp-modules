# UnpacMe Lookup

Find existing UnpacMe unpacking results for a SHA-256 hash.

Queries /api/v1/private/search/hash using Key authentication. max_results defaults to 25 (1-100). Each matching submission becomes a referenced annotation with its status, submission ID and timestamps. Unpacked child hashes become file objects linked to the original hash. Does not upload or download samples or wait for incomplete jobs. Result truncation is explicitly reported.

Input: sha256. Output: Submission annotations and unpacked-child file objects.

Configuration: apikey, max_results. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://api.unpac.me/

Example request:

```json
{
  "module": "unpac_me",
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

Validation: `pytest tests/test_unpac_me.py` uses mocked service responses;
no paid API credentials are needed.

Search records use `id` and an integer `children` count. Positive counts trigger one authenticated `/private/results/{id}` request to retrieve unpacked SHA-256 values from the result entries. Parent and duplicate hashes are excluded. Zero-child and pending submissions retain their ID and child count; unavailable result details do not trigger polling. Legacy child-hash lists remain supported.
