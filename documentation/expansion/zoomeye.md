# ZoomEye API v2

Expand IP addresses, domains, hostnames and SHA-1 certificate fingerprints.
The module uses `https://api.zoomeye.ai/v2/search` with an API-KEY header and
a Base64-encoded query. It does not use the legacy host-search endpoint.

| Setting | Purpose |
| --- | --- |
| `api_key` | Required ZoomEye API key; leading/trailing whitespace is removed. |
| `max_results` | First-page asset limit, 1–100; defaults to 20. |

IPv4 and IPv6 queries select their corresponding datasets. Domain searches use
the web dataset; hostnames and `x509-fingerprint-sha1` searches use all datasets,
including hosts observed on non-web services. Fingerprints
may contain colon separators. SHA-256 certificate search is not advertised
because the referenced API documentation demonstrates SHA-1 fingerprints.
Inputs are validated before constructing the query.

The module returns the source attribute, a referenced `ip-port` object per
asset and a search-coverage annotation. Service, banner, product, version,
OS, ASN, organization, certificate text and observation time are retained in
each asset's context when returned. New enrichment has `to_ids=false`.

Only one page is requested. When the service's total exceeds the returned
records, a truncation notice makes the incomplete coverage explicit.
The module does not automatically spend credits fetching additional pages.
HTTP errors and non-success API codes are errors; remote messages are not exposed.

Enable `zoomeye` in MISP's enrichment settings after restarting misp-modules.
Validate offline with `python -m pytest tests/test_zoomeye.py`.

[Official API v2 reference](https://github.com/zoomeye-ai/ZoomEye-python/blob/master/api.md)
