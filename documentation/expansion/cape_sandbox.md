# CAPE Sandbox Enrichment

Submit supplied samples to CAPEv2 or retrieve a completed JSON report by numeric task ID. Set api_url to the API v2 base, for example https://cape.example/apiv2. api_key is optional when the server permits unauthenticated requests. submit_samples defaults to false. max_size_mb defaults to 25 (1–100). Submission returns task IDs; use a text attribute containing a task ID for a later report lookup. Completed reports yield file hashes, network pivots and extracted configurations.

Input: text, attachment, malware-sample.

Configuration: api_url, api_key, submit_samples, max_size_mb, max_results. Required: api_url.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://capev2.readthedocs.io/en/latest/usage/api.html
