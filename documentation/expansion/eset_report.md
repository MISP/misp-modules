# ESET Threat Intelligence Report

Download an ESET ETI PDF from a supported report download link and return a file object with its content and SHA-256. Only HTTPS report paths on eti.eset.com, www.eset.com or eset.com are accepted. Portal report links are translated to the fixed API endpoint `https://eti.eset.com/api/v2/apt-reports/{uuid}/download/pdf`; credentials are sent only to that API host. Set api_token to the complete generated REST API token, without the Bearer prefix; it is forwarded unchanged. Redirects are rejected to keep credentials on the selected host. max_size_mb defaults to 25 (1–100); streamed responses are capped before importing. The report content hash supports duplicate detection when reviewing enrichment results.

Input: link.

Configuration: api_token, max_size_mb, max_results. Required: api_token.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://help.eset.com/eti_portal/en-US/

API specification: https://eti.eset.com/docs/api/public/v2

Portal links of the form `/reports/apt/download/{uuid}` are supported.
