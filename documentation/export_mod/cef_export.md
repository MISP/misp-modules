# CEF export

The exporter follows the [OpenText ArcSight CEF Implementation Standard, version 27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf), especially the header, file output, character encoding and extension dictionary sections (pages 5–10).

It produces a base64-encoded UTF-8 `.cef` file, with one line per supported attribute. It accepts a single event or a list of events: bare events, `{"Event": {...}}` wrappers, and legacy exports with `Attribute` or `Object` alongside `Event` metadata. Object attributes are included. As before, all supplied supported attributes are exported regardless of `to_ids`; unsupported types are ignored. Apply any desired filtering before export.

## Configuration

Missing configuration keys use these defaults. Explicit invalid values return a module error with no file.

| Setting | Default | Accepted values |
| --- | --- | --- |
| `Device_Vendor` | `MISP` | Non-empty string, at most 63 characters |
| `Device_Product` | `MISP` | Non-empty string, at most 63 characters |
| `Device_Version` | `1` | Non-empty string or integer, at most 31 characters |
| `Default_Severity` | `1` | Integer 0–10, numeric string 0–10, or `Unknown`, `Low`, `Medium`, `High`, `Very-High` |

Integer device settings are converted to strings for compatibility with existing configuration. Header values cannot contain line breaks or other ASCII control characters. Overlong fields are rejected rather than truncated. Length limits apply to the original field values before CEF escaping.

## Record mapping

The header is `CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|`.

The event-class ID is the MISP attribute type, so `ip-src`, `ip-dst`, and each hash algorithm remain distinguishable. The name is the attribute category (at most 512 characters), falling back to the type when the category is absent. The category is also exported as `cat`.

| MISP attribute type | CEF extension key | Limit |
| --- | --- | --- |
| `ip-src` | `src` | Single IPv4 or IPv6 address |
| `ip-dst` | `dst` | Single IPv4 or IPv6 address |
| `hostname`, `domain` | `dhost` | 1023 characters |
| `md5`, `sha1`, `sha256` | `fileHash` | 255 characters |
| `url` | `request` | 1023 characters |

IPv4 and non-address records use `CEF:0`. IPv6 address records use `CEF:1`, since CEF specification 1.x permits IPv6 in the standard address fields. Address values are normalized; CIDR networks and scoped IPv6 addresses cannot be represented as a single CEF address and return errors. String values retain their content, including Unicode, spaces and extension pipes. Hash, hostname and URL syntax validation remains the responsibility of the input producer; the exporter validates their CEF string type and length.

When an attribute has a `timestamp`, its non-negative Unix seconds are converted to milliseconds in `deviceCustomDate1`, labeled `MISP attribute timestamp` by `deviceCustomDate1Label`. This retains the year and avoids server timezone and locale dependence. A MISP attribute modification timestamp does not establish the time of an observed incident, so it is not mapped to `start`, `end`, or `rt`. Missing timestamps omit these two fields.

Header backslashes and pipes are escaped. Extension backslashes and equals signs are escaped, and CR/LF become literal `\r`/`\n` sequences. Pipes and spaces in extensions remain literal, as required by CEF. Invalid requests, control characters, unsupported header values, malformed addresses and overlong fields return `{"error": "..."}` without a partial file.

## Example

Submit this JSON to the misp-modules `/query` endpoint:

```json
{
  "module": "cef_export",
  "config": {"Default_Severity": "Medium"},
  "data": [{"Attribute": [{
    "type": "url",
    "category": "Network activity",
    "timestamp": "1700000000",
    "value": "https://example.org/?a=1&b=2"
  }]}]
}
```

The decoded `data` is:

```text
CEF:0|MISP|MISP|1|url|Network activity|Medium|request=https://example.org/?a\=1&b\=2 cat=Network activity deviceCustomDate1=1700000000000 deviceCustomDate1Label=MISP attribute timestamp
```

## Compatibility changes

Version 2 removes the fabricated `MMM dd HH:mm:ss host` syslog prefix. The standard's file export procedure starts each line with `CEF:` (page 8); an actual syslog sender should supply its own transport prefix. Collectors configured for the old prefix must be updated.

Rules matching the event-class ID must use the attribute type instead of the category. Rules matching the name can continue using the category. Consumers of IPv6 address records need CEF 1.x support. Invalid severity, header, address or string lengths now fail the export explicitly instead of producing malformed output. The `.cef` extension and base64 response envelope are retained; the advertised MIME type is corrected to `text/plain`.

These checks cover file serialization against the published specification. They do not constitute ArcSight certification or a live collector integration test.
