# Microsoft Defender for Endpoint KQL export

`defender_endpoint_export` generates Advanced Hunting queries locally. It does not contact Microsoft or execute queries. Supported MISP attribute types are `sha256`, `sha1`, `md5`, `domain`, `url`, `ip-src` and `ip-dst`, including attributes inside objects.

The base64 `data` response remains a `.kql` file with **one complete, independently executable query per line**. Select and run each line separately in Advanced Hunting, or submit each line separately through your own API client. Pasting the entire file into one request does not execute every batch as a separate search. Each query retains table columns and adds `MISP_SourceTable` through `union withsource`.

## Configuration

Pass these options in the request's `config` object or configure them for the module on the server. Omitted, null or empty-string options use defaults.

| Option | Default | Accepted values |
| --- | --- | --- |
| `Period` | `7d` | Positive integer followed by `d`, `h`, `m` or `s`, at most 30 days; for example `24h`. Arbitrary KQL expressions and fractional durations are rejected. |
| `start_time`, `end_time` | unset | Supply both instead of `Period`. ISO 8601 timestamps with seconds and an explicit timezone, such as `2026-01-01T02:00:00+02:00`. They are normalized to UTC. The interval must be positive and at most 30 days. Clear a configured `Period` when using these options. |
| `domain_mode` | `exact` | `exact` matches the apex hostname only. `subdomains` matches the apex and all subdomains, using DNS label boundaries. |
| `tables` | Endpoint tables and `AlertEvidence`, listed below | Comma-separated names or a JSON array selecting tables from the allowlist below. Only select tables available in your tenant. |
| `batch_size` | `100` | Integer from 1 to 500, or its decimal string representation. This bounds unique typed indicators per query. |

Every table branch applies `Timestamp between (MISP_Start .. MISP_End)` before a separate parenthesized indicator predicate. Both boundaries are inclusive. The same start/end definitions apply to all branches in a batch. Relative ranges are evaluated when each batch runs; use absolute timestamps for a fixed interval across multiple requests. The exporter caps ranges at 30 days; tenant retention and permissions still determine available results.

Example request:

```json
{
  "module": "defender_endpoint_export",
  "config": {
    "Period": "7d",
    "domain_mode": "subdomains",
    "tables": "DeviceNetworkEvents,DeviceFileEvents,AlertEvidence",
    "batch_size": 100
  },
  "data": [{
    "Event": {
      "Attribute": [
        {"type": "domain", "value": "example.org"},
        {"type": "url", "value": "https://example.org/CaseSensitivePath"}
      ]
    }
  }]
}
```

## Matching and table fields

Hash literals must have the correct hexadecimal length. They are normalized to lowercase and compared case-insensitively against file and initiating-process hashes only where those columns exist. `AlertEvidence` has SHA-1 and SHA-256 columns, but no MD5 column; `DeviceNetworkEvents` has initiating-process hashes, but no primary file hashes.

Domains are validated with IDNA UTS #46, without transitional mappings, lowercased and stripped of a final DNS root dot. Thus `faß.de` becomes `xn--fa-hia.de`, not `fass.de`. Telemetry hostnames are extracted with `parse_url`, handling full URLs, protocol-relative URLs and bare FQDNs, then lowercased and stripped of the root dot. Internationalized telemetry hostnames must be represented in ASCII/punycode to match the normalized indicator. A domain in a URL path, query parameter or unrelated hostname does not match. With `subdomains`, `example.org` matches `a.example.org` and `example.org`, but neither `badexample.org` nor `example.org.evil.test`. Wildcard domain indicators are rejected; select `subdomains` instead.

URLs must be absolute, have a valid host and port, and contain no whitespace or control characters. They match the complete stored string **case-sensitively**; the exporter does not decode percent escapes, normalize paths, remove fragments or equate a host-only observation with a full URL. Use a domain indicator when the intended scope is the hostname. Values are encoded as JSON dynamic arrays; generated KQL string literals escape quotes and backslashes.

IP literals must be individual IPv4 or IPv6 addresses; CIDRs and scoped addresses are rejected. IPv6 comparisons use `ipv6_is_match`, so expanded and compressed representations can match. IP roles follow the table's local/remote convention: `ip-src` searches local/client fields; `ip-dst` searches remote/origin-server fields. This is an endpoint-relative hunting convention, not a reconstruction of packet direction for inbound traffic. Use the appropriate MISP type for the intended field.

| Table | Hash fields | URL and domain fields | `ip-src` | `ip-dst` |
| --- | --- | --- | --- | --- |
| `DeviceEvents` (default) | `MD5`, `SHA1`, `SHA256` and their `InitiatingProcess` counterparts | `RemoteUrl`, `FileOriginUrl` | `LocalIP` | `RemoteIP`, `FileOriginIP` |
| `DeviceFileEvents` (default) | File and initiating-process hashes | `FileOriginUrl`, `FileOriginReferrerUrl` | — | `FileOriginIP` |
| `DeviceImageLoadEvents` (default) | File and initiating-process hashes | — | — | — |
| `DeviceProcessEvents` (default) | File and initiating-process hashes | — | — | — |
| `DeviceNetworkEvents` (default) | Initiating-process hashes only | `RemoteUrl` | `LocalIP` | `RemoteIP` |
| `AlertEvidence` (default) | `SHA1`, `SHA256` | `RemoteUrl` | `LocalIP` | `RemoteIP` |
| `EmailUrlInfo` (opt in) | — | `Url` | — | — |
| `UrlClickEvents` (opt in) | — | `Url` | `IPAddress` | — |

These mappings follow the [Microsoft Advanced Hunting schemas](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables). Email and click tables require the corresponding Defender services and must be explicitly selected. `AlertInfo` is alert metadata, and `DeviceAlertEvents` is not a current documented table; neither is queried. Tables without a matching field for a batch are omitted. A configured table must still exist and be accessible in the target tenant; the exporter cannot discover tenant-specific availability.

## Filtering, limits and response

Bare events, nested `Event` exports, legacy exports with sibling `Attribute`/`Object` collections, a single event, and event lists are accepted. Deleted envelopes, events, objects and attributes are skipped, including serialized flags such as `"1"` and `"true"`. Active attributes with `to_ids=false` remain eligible for hunting, preserving the module's previous behavior. Input is not modified.

Normalized `(type, value)` pairs are deduplicated and sorted across events and objects before batching. Each query is limited to 65,536 UTF-8 bytes as well as `batch_size`. Values are limited to 8,192 UTF-8 bytes and the request to 10,000 unique supported indicators. No indicators are silently truncated: invalid values and types, deletions, and indicators without a field in the selected tables are counted in `summary.skipped`. The additional `summary` response reports exported indicator and query counts; the downloadable file contains queries only. No usable indicators produces an empty file. Invalid request structures, configuration, deletion flags, total-limit violations or a single indicator that cannot fit in a query return an `error` without partial output.

## Validation

Run `pytest tests/test_defender_endpoint_export.py` for regression and HTTP-service tests. The [independent validator](../../tests/fixtures/defender_kql/README.md) uses Microsoft's `Microsoft.Azure.Kusto.Language` analyzer and a captured schema snapshot. It checks syntax, column resolution and types without a tenant. This does not verify live service availability, tenant permissions, query execution limits or actual matching against production telemetry.
