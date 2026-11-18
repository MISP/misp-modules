# BeaconBeagle lookup

Enrich MISP attributes with public Cobalt Strike observations from
[BeaconBeagle](https://beaconbeagle.com/api/). No API key is required.

| Attribute type | Lookup |
| --- | --- |
| `ip-src`, `ip-dst` | Beacon details and configurations, C2 details and associated configuration hashes |
| `domain`, `hostname` | C2 details and configuration text search |
| `url` | C2 details for the URL hostname and configuration text search for the complete URL |
| `sha256` | Exact **configuration hash** lookup; the API does not index malware sample hashes |
| `AS` | Network query by ASN, e.g. `AS64500` |
| `text` | Exact configuration-field pivot or country network query, as JSON below |

For arbitrary exact configuration-field pivots, set a `text` attribute to:

```json
{"path":"settings.SETTING_WATERMARK","value":987654321}
```

Other examples include `watermark`, `version`, `protocol`,
`settings.SETTING_USERAGENT` and `settings.SETTING_PUBKEY`. The API's
`GET /api/v1/supersearch/fields` lists available paths. Scalar values are sent as
strings to `/pivot`; complex field values are not inferred from arbitrary text.

For country facets, use a `text` attribute containing:

```json
{"countries":["FR","DE"]}
```

Example module request:

```json
{
  "module":"beaconbeagle",
  "attribute":{
    "type":"ip-dst",
    "value":"192.0.2.1",
    "uuid":"32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config":{"max_configs":10}
}
```

`max_configs` accepts 1–20, default 10. Expansion intentionally returns a bounded
set for interactive use. An annotation includes upstream totals, candidate hashes,
unavailable configurations and `limited=true` when more configurations exist.
ASN/country annotations also retain the returned beacon/C2 lists and totals.
Use gathering for bulk collection. Text search is BeaconBeagle's own matching
semantics; a returned configuration is evidence to review, not an exact IOC claim.
URL lookups also return host-level C2 evidence, which does not by itself prove
that the exact URL was observed.

Output preserves the input attribute and its metadata. Each decoded configuration
becomes a `malware-config` object; observed endpoints become `ip-port` objects.
Associated IPs, domains, URLs, HTTP user agents and ASN information are mapped where
available. Configuration locations accept hostnames as well as IP addresses.
C2 endpoint objects retain the hostname and each resolved IP with the endpoint's
port and protocol. ASN attributes include per-IP enrichment and are deduplicated.
Every source detail response is preserved as a canonical JSON attachment
with its API link, retaining timestamps, country/organisation enrichment, configuration
settings and fields without dedicated MISP relations. Objects reference the input
attribute. Generated attributes use `to_ids=false`; configuration hashes are not
added as sample hashes.

Only 404 detail responses mean no match. Other HTTP failures, malformed JSON and
invalid record shapes return an error. Requests verify TLS, reject redirects, use
finite timeouts and cap each decoded response at 16 MiB. No request is sent to
the queried infrastructure itself. The module uses the documented v1 detail,
search, pivot and network query endpoints; API health/statistics, batch retrieval,
facet discovery and compound SuperSearch queries are not expansion modes.
