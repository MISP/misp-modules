# FortiSandbox Enrichment

Authenticate to a FortiSandbox appliance and retrieve an existing rating by SHA-1 or SHA-256. Set api_url to the appliance HTTPS origin, without /jsonrpc. For supplied files, calculate SHA-256 and look up the rating first. submit_samples defaults to false; true permits submission when the rating is unknown. max_size_mb defaults to 25 (1–100). A submission receipt is returned without polling. Provider ratings remain in their original vocabulary.

Input: sha1, sha256, attachment, malware-sample.

Configuration: api_url, username, password, submit_samples, max_size_mb, max_results. Required: api_url, username, password.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://www.fortinet.com/products/sandbox/fortisandbox

MD5-only lookup is not supported by the appliance single-file rating endpoint.
