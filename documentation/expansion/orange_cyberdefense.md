# Orange Cyberdefense Datalake

Look up indicators in the Orange Cyberdefense Datalake API.

Queries the documented mrti/threats/lookup endpoint using a long-term token in the Authorization header and requests JSON. IPs, domains and hashes are normalized before exact lookup. Scores, whitelisting, classifications, source evidence and other returned context remain in a referenced annotation; scores do not automatically change MISP IDS flags.

Input: domain, hostname, ip-src, ip-dst, url, md5, sha1, sha256, email-src, email-dst.

Configuration: token. Required: token.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://datalake.cert.orangecyberdefense.com/
- https://github.com/cert-orangecyberdefense/datalake

Example request:

```json
{
  "module": "orange_cyberdefense",
  "attribute": {
    "type": "domain",
    "value": "example.com",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "token": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_orange_cyberdefense.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

Supply the raw long-term token in `token`; the module adds the `Token` authorization scheme.

The current API contract is at https://datalake.cert.orangecyberdefense.com/api/v3/docs/swagger.json and defines `/v3/mrti/threats/lookup/` relative to the `/api` host. Hostname inputs use `domain`: the current atom-type enum includes `domain` and does not include `fqdn`. The obsolete v2 endpoints return HTTP 404.
