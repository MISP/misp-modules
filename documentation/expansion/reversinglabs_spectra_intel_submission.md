# ReversingLabs Spectra Intelligence Submission

Submit a file hash, URL or attachment to ReversingLabs Spectra Intelligence dynamic analysis.

url defaults to https://data.reversinglabs.com; platform defaults to windows10. Uses Basic authentication. mode=submit (default) submits an existing cloud sample by hash or a URL; attachments are uploaded to /api/spex/upload/{sha1} before detonation. max_size_mb defaults to 25 (1-100). mode=report retrieves the latest completed report by hash or URL. The returned analysis receipt can be pending; no polling or retries create duplicate submissions. Submission may consume service credits.

Input: md5, sha1, sha256, url, attachment.

Configuration: username, password, url, platform, mode, max_size_mb. Required: username, password.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.reversinglabs.com/SpectraIntelligence/API/

Example request:

```json
{
  "module": "reversinglabs_spectra_intel_submission",
  "attribute": {
    "type": "sha256",
    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "username": "YOUR_USERNAME",
    "password": "YOUR_API_KEY",
    "mode": "report"
  }
}
```

Validation: `pytest tests/test_reversinglabs_spectra_intel_submission.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

Attachment submission posts raw bytes, then XML filename metadata with an empty domain to `/api/spex/upload/{sha1}/meta`, and only then requests detonation. Metadata failures stop the submission. Supported platforms follow TCA-0207: `windows11`, `windows10`, `windows7`, `macos11`, `linux`, and `android12`.
