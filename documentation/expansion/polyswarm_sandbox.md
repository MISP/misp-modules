# PolySwarm Sandbox

Retrieve PolySwarm sandbox tasks or submit an existing PolySwarm sample for sandbox analysis.

mode defaults to lookup: SHA-256 inputs retrieve the latest sandbox task; text inputs retrieve a task by ID. provider defaults to triage. mode=submit submits a SHA-256 already present in PolySwarm using its scan instance ID and requires provider and vm. community defaults to default. Task status, report and provenance are returned without polling. Submission can consume service credits; no file is downloaded or uploaded.

Input: sha256, text.

Configuration: apikey, community, mode, provider, vm. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.polyswarm.io/

Example request:

```json
{
  "module": "polyswarm_sandbox",
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

Validation: `pytest tests/test_polyswarm_sandbox.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

Hash-based submission requires a stored scan in the chosen community. The API request uses its scan instance ID in the service field `artifact_id`. Binary uploads are outside this module; unknown hashes return an explicit submission error.
