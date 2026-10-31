# GreyNoise Vulnerability Intelligence

Retrieve dedicated GreyNoise CVE intelligence, including available exploitation activity, exploit counts, product details and prioritization fields. Provider fields are preserved in a referenced annotation. Coverage depends on the API key entitlement. An absent CVE returns no enrichment and does not imply no exploitation.

Input: vulnerability.

Configuration: api_key. Required: api_key.

New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://docs.greynoise.io/reference/getcve

One complete provider report is retained per lookup; there is no result-count setting.
