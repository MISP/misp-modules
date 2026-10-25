# Kaspersky Threat Intelligence Portal

Retrieve Kaspersky commercial Threat Intelligence Portal reports.

Uses Bearer authentication with GET /api/hash, /api/ip, /api/domain or /api/url and explicit report sections. url defaults to https://tip.kaspersky.com. Requires a commercial TIP key; this is separate from the public OpenTIP API. File hashes, sizes and names become file objects; DNS resolutions become domain-ip objects. Zone, license/quota and report sections are retained as provider context without changing detection flags. max_results defaults to 25 (1-100) for files and DNS resolutions.

Input: md5, sha1, sha256, ip-src, ip-dst, domain, hostname, url.

Configuration: apikey, url, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://tip.kaspersky.com/

URL FilesDownloaded rows become bounded file objects. Filename sections accept both FileName and FileNames response fields, including lists of names.
