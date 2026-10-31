# OWASP CRS export

`owasp_crs_export` converts IDS-marked MISP event and object attributes into a
ModSecurity `.conf` fragment to include alongside OWASP CRS. It generates custom
phase 1 rules that log and deny matching requests with HTTP 403. These rules act
directly, independently of CRS anomaly scoring and thresholds. They do not modify
CRS, load configuration, resolve DNS or contact an external service.

## Supported attributes

| MISP type | ModSecurity match |
| --- | --- |
| `ip-src` | `REMOTE_ADDR` with `@ipMatch`: client IPv4/IPv6 address or CIDR network |
| `ip-src\|port` | Client address/network **and** `REMOTE_PORT`, joined in a rule chain |
| `domain` | `REQUEST_HEADERS:Host`: domain and its subdomains, optionally followed by a port |
| `hostname` | `REQUEST_HEADERS:Host`: exact hostname, optionally followed by a port |
| `hostname\|port` | Exact hostname and **explicit** port in the Host header |
| `url` | Exact HTTP(S) authority **and** raw request path/query, joined in a rule chain |
| `uri` | Exact origin-form `REQUEST_URI_RAW` (path and optional query) on any host |
| `user-agent` | Exact, case-sensitive `REQUEST_HEADERS:User-Agent` |

Only attributes with `to_ids=true`, `1`, `"true"` or `"1"` are exported. Boolean
strings are case-insensitive. Missing/false flags are excluded, and there is no
override to include non-IDS attributes. The module never changes input flags.
Deleted events, objects and attributes are excluded. Each object attribute is
processed independently; separate attributes are not combined into an inferred
connection. Composite values must validate completely before a rule is emitted.

`REMOTE_ADDR` and `REMOTE_PORT` describe the client connection visible to the
ModSecurity connector. Behind another proxy, these may identify that proxy.
The exporter does not trust `X-Forwarded-For` or configure real-client-IP handling.
For source port composites, the port is the client's source port, not the
server's listening port.

Host rules match the requested HTTP authority; they do not inspect DNS answers
or resolve a destination address. `ip-dst`, `ip-dst|port` and `domain|ip` are
unsupported: `SERVER_ADDR` is the local server address and cannot reliably
represent a forward proxy's upstream destination. Standalone ports, hashes,
email addresses and other types are also skipped.

## Matching and validation

Addresses and networks are normalized. DNS names must be qualified and are
normalized to lowercase ASCII IDNA; Host matching ignores case and allows a
trailing DNS dot. Domain matches have label boundaries, so `example.org` does not
match `evilexample.org` or `example.org.other.test`. Ports range from 1 to 65535.
`hostname|port` requires an explicit `:port` in Host; it does not infer omitted
default ports from the proxy's local listening socket.

URLs must be absolute HTTP(S) without credentials or scoped IPv6 addresses.
Default ports may be absent from Host; non-default ports must be explicit. Empty
paths become `/`, and fragments are removed because clients do not send them.
Paths and queries retain their case, encoding and query order. Empty query
delimiters are preserved. Both origin-form (`/path?query`) and absolute-form
(`https://example.org/path?query`) request targets are accepted. Absolute-form
matches retain the indicator's scheme. Origin-form requests carry no scheme, so
these URL rules cannot distinguish HTTP from HTTPS for that form. They match
the same authority/path/query on either transport. They do not read forwarded
scheme headers. For IP-literal URLs, the Host text uses the normalized IP
representation (bracketed for IPv6); alternative IPv6 spellings are not expanded.

Exact raw matching does not decode percent escapes, normalize paths or fold
query order. Equivalent application URLs may require separate indicators.
`uri` accepts an ASCII origin-form target beginning with `/`, without a fragment.
URL paths/queries and URIs must use valid ASCII URI characters and percent
escapes; non-ASCII text must be percent-encoded. User agents may contain printable
ASCII, including spaces. Control characters and malformed values are rejected.
Indicator literals are escaped for both ModSecurity's tokenizer and PCRE,
including quotes, regex metacharacters and `%{...}` macro syntax. Each rule uses
`t:none` to reset inherited transformations.

HTTPS CONNECT tunnels hide request headers and paths without separately
configured TLS inspection. URL rules are not expanded into host-wide blocks.
The exporter does not configure TLS inspection, a proxy or CRS itself.

## Module API

Send a request to the misp-modules `/query` endpoint:

```json
{
  "module": "owasp_crs_export",
  "config": {"rule_id_start": "10000"},
  "data": [
    {
      "Event": {
        "Attribute": [
          {"type": "ip-src", "value": "192.0.2.0/24", "to_ids": true},
          {"type": "url", "value": "https://example.org/payload", "to_ids": true},
          {"type": "domain", "value": "context.example", "to_ids": false}
        ]
      }
    }
  ]
}
```

`data` accepts a single event or a list, bare events, standard `Event` wrappers,
and legacy exports with `Attribute`/`Object` beside `Event`. Object attributes
are included. The module is discovered automatically and needs no credentials
or additional Python dependencies.

The response's `data` is a base64-encoded ASCII configuration file.
`summary.count` counts unique rules (a complete chain counts as one), and
`summary.skipped` counts non-IDS, deleted, unsupported and malformed attributes.
Whole deleted events/objects are ignored before counting their attributes.
Warnings explain skipped values and integration limitations. Invalid request
structure, invalid flags or invalid configuration returns an `error` without a
file. Empty events produce comments only.

Rules are deduplicated and sorted before assigning consecutive IDs.
`rule_id_start` defaults to `10000` and accepts an integer or decimal string from
`10000` to `99999`. IDs stay within this local range, outside CRS's `900000-999999`
range; exports that would exceed `99999` fail without a file. A chain uses one
ID. Reserve the entire used range across all loaded custom rules. Identical
inputs produce identical output, but adding/removing an indicator can shift IDs.
Replace the previous fragment rather than including multiple generations. Use
non-overlapping ranges for separately loaded exports.

## Integration

Decode the response to `/etc/modsecurity/misp-ioc.conf`. Include it after your
ModSecurity engine configuration and `crs-setup.conf`, before the CRS rule files
and before any local rule that disables the engine or skips request inspection:

```apache
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/misp-ioc.conf
Include /etc/modsecurity/crs/rules/*.conf
```

Adapt paths and include syntax to your connector. The generated fragment does
not set `SecRuleEngine`: `On` is required to block, `DetectionOnly` evaluates
and logs without blocking, and `Off` disables inspection. Existing exceptions,
rule removals and engine controls still apply. Validate the complete deployed
configuration before reloading it, for example with `apachectl -t` or `nginx -t`.
