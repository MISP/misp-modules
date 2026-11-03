# Plum Island Search

`plum_island_search` searches existing Plum observations through the read-only
Discovery API v1 structured `search` endpoint. It returns matching IPs as
`ip-dst` attributes (`to_ids=False`) and referenced annotations with matching
document UIDs, observation timestamps, requested hostnames and actual date scope.
The original attribute and its metadata are preserved. Matches are evidence
of historical observations, not automatic maliciousness classifications.

## Inputs and queries

| MISP input | Exact Plum query |
| --- | --- |
| `domain` | `(domain:example.org OR domain_requested:example.org)` |
| `hostname` | `(fqdn:www.example.org OR fqdn_requested:www.example.org)` |
| `ip-src`, `ip-dst` | `ip:192.0.2.1`, or `net:192.0.2.0/24` for a CIDR |
| `x509-fingerprint-md5` | `x509_md5:<fingerprint>` |
| `x509-fingerprint-sha1` | `x509_sha1:<fingerprint>` |
| `x509-fingerprint-sha256` | `x509_sha256:<fingerprint>` |

Domain/hostname inputs are validated and normalized to lowercase IDNA. A domain
query searches Plum's registered-domain indexes, including certificate-derived
names; use `hostname` for exact fully qualified names. Certificate fingerprints
are normalized to lowercase without colon separators. Generic file hash types
are not accepted because Plum's `x509_*` indexes describe certificates. No
arbitrary query syntax is interpolated from input values.

## Setup and scope

Requires the Discovery API v1 added after Plum Island v0.2610.0 and `can_search`
on `DiscoveryApi`. See [IP History setup](plum_island.md) for authentication,
deployment and TLS behavior. Enable `Plugin.Enrichment_plum_island_search_enabled`.
The module identifier is `plum_island_search`, display name **Plum Island Search**.

Configuration: `url`, `username`, `password`, `access_token`, `max_results`,
`max_pages`, `from_ts`, `to_ts`. `url` and either account credentials or a FAB
JWT are required. `max_results` is a **total IP limit**, default 25 (1–100).
`max_pages` defaults to 10 (1–20). `from_ts` and `to_ts` are UTC epoch seconds;
when omitted, Plum searches its default last-three-calendar-month interval.
The controller normalizes time bounds using its existing whole-day rules.

Search discovers matches in backward `last_seen` windows. This differs from the
full interval-overlap exports and IP-history date filtering. Empty windows can
have a continuation: this module continues until `next_cursor` is null or a
configured budget is reached. Continuations send only the signed cursor and
remaining IP limit, preserving the controller's original query/date scope.
Private signed cursors and JWTs are not included in returned MISP evidence.

Each result includes a summary with `returned` and `complete`. A budget stop
sets `complete: false`, including a stop after empty windows. An incomplete
empty result does not establish that no observations exist. Narrow the date
range or raise the budget to investigate further. Backend errors remain module
errors; they are not converted into successful empty results.

Example `/query` request:

```json
{
  "module": "plum_island_search",
  "attribute": {
    "type": "domain",
    "value": "example.org",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "url": "https://plum.example.org",
    "access_token": "YOUR_FAB_JWT",
    "max_results": "25",
    "max_pages": "10"
  }
}
```

No active scan, DNS lookup, WHOIS or PDNS enrichment is performed. Use
`plum_island` on a returned IP to retrieve its raw documents and UID-level tags,
selecting the requested hostname group explicitly when needed.

Reference: [Plum Island Discovery API](https://github.com/D4-project/Plum-Island/blob/main/documentation/discovery.md).
