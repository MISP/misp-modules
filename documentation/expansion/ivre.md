# IVRE

Retrieve active scan observations from an IVRE web API.

url is the complete HTTPS view endpoint, for example https://ivre.example/cgi/view. Sends a structured f filter (host or domain) and q=limit:N, with JSON output and string dates. Optional username/password use HTTP Basic authentication. max_results defaults to 25 (1-100). Returns domain-ip and ip-port objects for open ports, with scan context in annotations. This module performs no scans and requires the IVRE view API to be exposed.

Input: ip-src, ip-dst, domain, hostname.

Configuration: url, username, password, max_results. Required: url.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://doc.ivre.rocks/en/latest/usage/web-ui.html
- https://github.com/ivre/ivre/blob/master/ivre/web/app.py
