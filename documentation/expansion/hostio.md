# Host.io

Retrieve Host.io DNS, website and co-hosted domain observations.

Uses Bearer authentication and GET /api/full/{domain} or /api/domains/ip/{ip}. max_results defaults to 5 (1-100), matching the free plan page size. A single page is requested; a notice identifies additional domains. DNS records become a dns-record object; website, IPinfo and related-domain metadata remain in a referenced annotation.

Input: domain, hostname, ip-src, ip-dst.

Configuration: apikey, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://host.io/docs

IP lookups round the requested page size up to a supported Host.io size (1, 5, 10, 25 or 100), then cap the returned objects to max_results.
