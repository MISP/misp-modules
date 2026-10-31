# DNSlytics Domain Search

Run an explicit DNSlytics domain dataset query supplied as a text attribute. One request retrieves page 1; at most max_results domains are imported. Domain metadata preserves active or dropped status when supplied. The premium endpoint consumes credits; a local cap does not reduce the provider charge. This initial module does not perform additional DNS or IP2ASN requests.

Input: text.

Configuration: api_key, max_results. Required: api_key.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://dnslytics.com/api
