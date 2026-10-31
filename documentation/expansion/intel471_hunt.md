# Intel 471 Hunter

Retrieve Intel 471 Hunter hunt packages, Sigma rules and analyst guidance.

Uses GET /es/query with Authorization: API-Key and indexes=cyborg_usecases. CVEs use exploit_or_vulns; text uses search_type, default mitre_technique_ids, with actors, threat_names, mitre_technique_names and mitre_tactic_names also supported. max_results defaults to 25 (1-100). Sigma rules become sigma objects; package metadata and runbooks are preserved in annotations. Requires a Hunter subscription, separate from Titan IOC access.

Input: vulnerability, text.

Configuration: apikey, search_type, max_results. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://hunter.cyborgsecurity.io/
- https://api.hunter.cyborgsecurity.io/docs

The Hunter request includes size=max_results. A truncation notice is also emitted if the service returns fewer records than the reported total.
