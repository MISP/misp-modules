# VMRay Analyzer Lookup

Retrieve existing VMRay sample and analysis context by file hash.

Set url to the HTTPS VMRay server URL and apikey to its API key. Queries /rest/sample/{hash-type}/{hash}, followed by /rest/analysis/sample/{sample_id}. Returns sample hashes, names, classifications, threat names, score, analysis status and report links. max_results defaults to 25 (1-100) for samples and analyses; continuation pages are reported as truncated. This lookup does not submit samples or wait for pending analyses. For full artifact import, use the VMRay import module.

Input: md5, sha1, sha256. Output: File objects, report links and referenced analysis annotations.

Configuration: apikey, url, max_results. Required: apikey, url.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://www.vmray.com/

Example request:

```json
{
  "module": "vmray_analyzer",
  "attribute": {
    "type": "sha256",
    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "apikey": "YOUR_API_KEY",
    "url": "https://cloud.vmray.com"
  }
}
```

Validation: `pytest tests/test_vmray_analyzer.py` uses mocked service responses;
no paid API credentials are needed.
