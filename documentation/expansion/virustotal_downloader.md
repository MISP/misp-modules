# VirusTotal Sample Downloader

Download an existing file from VirusTotal by hash.

Requires a VirusTotal API key with file download entitlement. Uses GET /api/v3/files/{hash}/download. Streams at most max_size_mb (default 50, range 1-100) and verifies the downloaded file against the requested hash. Signed HTTPS redirects are followed without forwarding the API key. Returns raw bytes as a MISP attachment in a file object with MD5, SHA-1 and SHA-256 hashes; no sample is executed or submitted.

Input: md5, sha1, sha256. Output: A file object with a binary attachment and verified hashes.

Configuration: apikey, max_size_mb. Required: apikey.
Requests use a 30 second timeout and verify TLS certificates. Errors distinguish
missing configuration, invalid input, authentication failures, rate limits and
invalid responses. No API credentials are included in error messages.

All new enrichment attributes use `to_ids=false`. Source attributes retain their
UUID and metadata. Returned objects reference the source attribute where possible.
Empty lookups return the source attribute without fabricated enrichment.

References:

- https://docs.virustotal.com/reference/files-download

Example request:

```json
{
  "module": "virustotal_downloader",
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

Validation: `pytest tests/test_virustotal_downloader.py` uses mocked service responses;
no paid API credentials are needed.
