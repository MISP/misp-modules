# Criminal IP Enrichment

Retrieve IPv4 risk and infrastructure reports, existing domain scan listings, or a completed domain scan by numeric text ID. Provider JSON retains risk scores, flags and available vulnerability data. submit_unknown defaults to false; true submits a domain only when its report listing is empty. Submission returns a scan receipt without polling. Use its scan_id as text input to retrieve the full report.

Input: ip-src, ip-dst, domain, hostname, text.

Configuration: api_key, submit_unknown, max_results. Required: api_key.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://www.criminalip.io/developer/api
