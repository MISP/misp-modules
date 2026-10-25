# Palo Alto WildFire

Retrieve WildFire verdicts and XML reports, or submit an attachment for analysis.

url defaults to https://wildfire.paloaltonetworks.com/publicapi and can select a regional cloud or appliance. Hashes query get/verdict and get/report; unknown (-102) and pending (-100) verdicts remain distinct from benign verdicts. Attachment inputs submit raw base64-decoded bytes to submit/file and return the sample hash for a subsequent lookup. max_size_mb defaults to 25 (1-100). No polling or automatic resubmission is performed.

Input: md5, sha256, attachment.

Configuration: apikey, url, max_size_mb. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api

Example request:

```json
{
  "module": "paloalto_wildfire",
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

Validation: `pytest tests/test_paloalto_wildfire.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

For an appliance with a private certificate authority, set `ca_bundle` to an existing PEM CA-bundle file on the module server. The file is used for both lookups and submissions. Leaving the option unset uses the default trust store; TLS verification remains enabled.
