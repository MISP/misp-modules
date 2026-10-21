# ONYPHE enrichment

The `onyphe` and `onyphe_full` expansion modules follow the [ONYPHE OpenAPI reference](https://github.com/onyphe/material/tree/master/openapi), version 2026-10-21.

`onyphe` uses Search by default: `ctiscan` for IPs, hostnames, CPEs and certificate fingerprints; `ctiurl` for URLs; `riskscan` and `vulnscan` for registrable domains. Set `mode=summary` to retain the previous Summary lookup for IPs, domains and hostnames. Summary does not return ctiscan/ctiurl data.

`onyphe_full` searches ctiscan, ctiurl, riskscan, vulnscan, datascan, resolver, ctl, pastries and threatlist for IPs and hostnames. Domains use the flat categories because the specification does not define a registrable-domain filter for the ctiscan model. URLs use ctiurl; CPEs and X.509 fingerprints use ctiscan and ctiurl. Its optional `categories` configuration is a comma-separated subset of those categories. A domain query configured with ctiscan/ctiurl is rejected before searching.

Both modules accept IP, domain, hostname, URL, CPE and X.509 MD5/SHA-1/SHA-256 fingerprint attributes. Inputs are quoted as OQL values. The client handles v2 Bearer authentication and pagination; requests are paced to one Search request per second. The modules do not send input values as free-text queries.

| Configuration | Default | Meaning |
| --- | --- | --- |
| `apikey` | Required | ONYPHE API key |
| `limit` | `100` | Maximum documents per category, clamped to 1–10,000 |
| `timeout` | `30` | Per-request timeout in seconds, greater than 0 and at most 300 |
| `since` | Empty | Optional rolling history, for example `7d`, `1w`, `3M`; otherwise Search covers 30 days |
| `mode` | `search` | Basic module only: `search` or legacy `summary` |
| `categories` | Depends on input | Full module only: comma-separated category names |

Search settings apply to Search mode. Legacy Summary mode uses the SDK defaults. A comment indicates when a category reaches the configured result limit; additional records may exist. An empty population is a successful result. Subscription denials produce a partial-results comment. Invalid credentials, exhausted credit, malformed queries, rate limits and transport failures return errors.

## MISP object mapping

Install the bundled `misp_modules/data/onyphe/onyphe-service/definition.json` template in MISP until it is available through a misp-objects update. The module loads this bundled definition locally, so its parser does not depend on a new PyMISP release.

| Object | Purpose |
| --- | --- |
| `onyphe-service` | One service or URL observation, retaining category, service port, application protocol, products/CPEs, HTTP metadata, observation dates, risk/verdict tags and the complete returned document as a JSON attachment |
| `ip-port` | Generic endpoint and network context; linked from a service with `observed-on` |
| `x509` | Certificate fingerprints, issuer/subject, public key and validity; linked from a service with `presents` |
| `vulnerability` | Deduplicated CVE identifier, linked to every relevant observation |
| `domain-ip` | Legacy DNS resolution associations |

For ctiscan/ctiurl, fields come from `ip.*`, `tcp.*`, `app.*`, `component.*`, `http.*`, `html.*`, `cert.*` and `dns.*`. The flat models use `ip`, `port`, `protocol`, `cpe`, `cve` and related fields. `services.port` describes the whole host and is never substituted for the port of this service. Parallel component arrays are retained independently; their elements are not paired into invented software instances. Certificate SAN IPs are never inferred from the serving IP. Ambiguous multi-valued single-certificate fields remain in the source JSON.

The [CTI data model](https://search.onyphe.io/docs/data-models/ctiscan) defines `dns.hostname` as the primary resolved hostname. Hostname searches include it alongside forward/reverse DNS fields; service and endpoint objects retain the combined, deduplicated names. Layered CVEs come from `component.cve`, and transport comes from `app.transport` without inferring TCP from a port. Certificate serial numbers use `cert.serial.hex`, falling back to `cert.serial.num`; legacy scalar serial values remain supported.

A CVE mention alone does not assert that the service is vulnerable. Only a `vulnerable` check verdict (without a contradictory negative verdict), or the documented positive-only riskscan model, creates an `affects` reference. Negative, uncertain and version-based verdicts use `related-to`, retaining the exact verdict tags in the service observation. Repeated observations on different dates remain distinct; shared certificates and CVEs retain links to each service. Derived Search attributes have `to_ids=False`.

The JSON attachment preserves the returned document, including data not extracted into attributes. Datascan `data` can be truncated upstream at 16,384 bytes; the module cannot recover missing bytes. Observations describe what ONYPHE saw at a particular time, not the current state of an asset. No native MISP detection tags or vulnerability sightings are inferred from ONYPHE tags.

## Endpoint scope

Attribute enrichment uses bounded Search. The specification's other endpoints serve separate workflows: Export streams a complete population as NDJSON, Discovery accepts a bulk asset inventory, and ASD returns distinct pivot values using the v1 endpoint and `X-Api-Key` authentication. These modules do not invoke those endpoints automatically or submit bulk inventories. Use those dedicated APIs when the Search ceiling is insufficient.
