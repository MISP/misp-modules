# DomainTools Iris enrichment

The bundled Iris modules use the service selection, pivot filters and field conventions in the [DomainTools reference integration](https://github.com/DomainTools/domaintools_misp). They return MISP objects with references to the original attribute.

## Choose a module

| Module | Input | Service and entitlement |
| --- | --- | --- |
| `domaintools_iris_enrich` | domain | Iris Enrich; requires Iris Enrich account provisioning |
| `domaintools_iris_investigate` | domain | Iris Investigate; requires Iris Investigate account provisioning |
| `domaintools_iris_pivot` | domain, IP, hostname, registrant email/name, registrar or certificate SHA-1 | Iris Investigate; requires Iris Investigate account provisioning |

Enrich and Investigate support expansion and hover. Pivot supports expansion. A hostname passed to Pivot searches the provider's `nameserver_host` field; it does not query that hostname as a domain. IPs map to `ip`, emails to `email`, registrars to `registrar`, registrant names to `registrant`, and certificate SHA-1 fingerprints to `ssl_hash`. Domain inputs use the exact normalized domain, without silently reducing it to a parent domain.

## Configuration and use

Enable the selected module in MISP Plugin Settings and configure `username` and `api_key`. Iris subscriptions and legacy Enterprise API entitlements are separate; a working legacy key does not establish entitlement to every Iris product.

`results_limit` defaults to 100 and accepts 1–100. One request retrieves the first result page. Investigate requests set `page_size` to this limit; imported domain rows and individual typed field collections are capped locally. An annotation preserves available total counts, missing domains, quota indicators and pagination position. The module does not automatically fetch additional pages.

Pivot also accepts `guided_pivot_threshold`, default 300, in the range 0–100000. Positive provider counts below the threshold receive the `Guided Pivot` tag and a count comment. Zero disables these tags. Counts and tags identify investigation leads; they do not assert maliciousness.

The module server sends requests to fixed HTTPS API endpoints using POST form data. TLS verification is enabled, redirects are rejected, connection/read timeouts are 5/30 seconds, and failed requests are not automatically retried. Errors do not copy credential-bearing request URLs, response bodies or exception details.

## Results

Domain and IP observations use `domain-ip` objects. WHOIS dates, registrars and registrant contacts use `whois` objects. MX and nameserver observations use separate `domain-ip` objects; Pivot also emits certificate hashes as `x509` objects and redirect domains as domain observations.

A referenced annotation retains each imported domain's provider JSON, including risk score components, evidence, hosting context and Guided Pivot counts. This preserves zero scores and false flags. The raw domain record remains complete even when typed field collections reach the local cap.

The source attribute retains its UUID, metadata and detection flag. New attributes use `to_ids=false`. Empty lookups preserve the source without asserting that it is benign.

## Legacy module and full provider suite

The existing `domaintools` module continues to use the legacy Enterprise endpoints for WHOIS, reputation and reverse lookups. Use the Iris modules above for Iris services.

The provider's full suite also offers Iris Import and Iris Detect, plus legacy Analyze, Pivot and Historic modules. To install that suite separately, follow the [provider installation instructions](https://github.com/DomainTools/domaintools_misp#installation-instructions) in the same Python environment as the module server. The documented package names are `domaintools_api` and `domaintools_misp`; load its `install/modules` directory with the module server's `-c` option. Review the provider's paths and migration instructions for your installation before modifying deployed files.

Reference implementation reviewed: [commit 7586943a7071](https://github.com/DomainTools/domaintools_misp/tree/7586943a7071c120261a29538b9f9f56ccf4c6b3), especially `iris_enrich.py`, `iris_investigate.py`, `iris_pivot.py`, `base.py` and `constants.py`. The bundled adapters implement the observed API conventions with native MISP object output; they do not require the separate `domaintools_misp` package.
