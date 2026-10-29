# ANY.RUN Threat Intelligence Lookup

Search ANY.RUN threat intelligence for existing observations without submitting a sandbox task. lookup_days defaults to 180 (1–365). Each result section is capped by max_results. Returned summaries preserve provider threat levels, tags and observation dates.

Input: domain, hostname, ip-src, ip-dst, url, md5, sha1, sha256.

Configuration: api_key, lookup_days, max_results. Required: api_key.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://github.com/anyrun/anyrun-sdk
