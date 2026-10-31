# Hybrid Analysis Sandbox

Look up Hybrid Analysis reports or submit a file or URL for sandbox analysis.

Hashes use GET /search/hash; text accepts a report ID (job ID or SHA256:environment-ID) and uses GET /report/{id}/summary. Files and URLs use POST /submit/file and /submit/url, returning the receipt without polling or retrying a submission. environment_id defaults to 110. max_results defaults to 25 (1-100); max_size_mb defaults to 25 (1-100). Reports and receipts become sandbox-report objects with links. Submissions send the supplied content to the service under your account sharing policy.

Input: md5, sha1, sha256, attachment, url, text.

Configuration: apikey, environment_id, max_results, max_size_mb. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://hybrid-analysis.com/docs/api/v2

Text report lookups accept the API job_id (24 hexadecimal characters) or the legacy SHA256:environment-ID form.
