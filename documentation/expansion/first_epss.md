# FIRST EPSS Lookup

Query FIRST directly for a CVE EPSS probability, percentile and score date without requiring another vulnerability service. EPSS estimates exploitation probability over the next 30 days. Values remain in the provider range 0–1. The module reuses the bundled epss-score template. An empty response does not become a zero score.

Input: vulnerability.

Configuration: max_results. Required: none.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://www.first.org/epss/api
