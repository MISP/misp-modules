# Censys Enrichment APIs

Retrieve Censys host enrichment, web properties on ports 80 and 443, or certificate metadata. Configure a platform API token and organization ID. Host service results are bounded; the annotation retains provider fields including scores and labels when present. Web property and certificate requests may consume standard credits under the account plan.

Input: ip-src, ip-dst, domain, hostname, x509-fingerprint-sha256.

Configuration: api_token, organization_id, max_results. Required: api_token, organization_id.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://docs.censys.com/reference/v3-globaldata-asset-host-enrichment
