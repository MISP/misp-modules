# LastInfoSec

Retrieve LastInfoSec STIX 2.1 intelligence and convert it to MISP.

Posts {value: observable} to /stix21/search/ at url (default https://api.client.lastinfosec.com/v2). The legacy API requires api_key in query parameters; configure proxy and access-log redaction accordingly. HTTP 422 means no match. Converts all returned message bundles up to max_results (default 25, 1-100), preserving relationships and markings with misp-stix and indicating partial conversions. Requires a working legacy LastInfoSec endpoint and subscription.

Input: md5, sha1, sha256, ip-src, ip-dst, domain, hostname, url.

Configuration: apikey, url, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. The legacy API requires the API key as a query parameter; redact query strings in proxy/access logs. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://api.client.lastinfosec.com/v2/
