# Squid proxy export

`squid_export` converts IDS-marked MISP event and object attributes into a Squid
`.conf` fragment containing `acl` definitions and `http_access deny` rules.
It requires no additional Python packages, performs no network requests and does
not load rules or change the proxy.

## Supported attributes

| MISP type | Squid match |
| --- | --- |
| `ip-src` | `src`: client IPv4/IPv6 address or CIDR network |
| `ip-dst` | `dst`: destination IPv4/IPv6 address or CIDR network |
| `ip-dst\|port` | Destination address/network **and destination port** |
| `domain` | `dstdomain -n .example.org`: domain and its subdomains |
| `hostname` | `dstdomain -n host.example.org`: exact hostname |
| `domain\|ip` | Domain (including subdomains) **and** supplied destination address/network |
| `hostname\|port` | Exact destination hostname **and destination port** |
| `url` | Anchored, case-sensitive `url_regex` for an exact HTTP(S) URL |
| `port` | Destination port on **all hosts** |

Composite attributes generate separate ACLs joined with AND on one deny line.
They are never split into independent blocks. Each object attribute is processed
independently; separate attributes are not joined into an inferred connection.
`ip-src` refers to the client address seen by Squid, rather than an upstream
server or the source address of arbitrary packets. Destination port ACLs refer
to the requested server port, including the target port of CONNECT requests.

Only attributes whose `to_ids` flag is `true`, `1`, `"true"` or `"1"` are included
(boolean strings are case-insensitive). Missing/false flags are excluded, and
there is no option to include non-IDS attributes. The exporter does not modify
the supplied flags. Deleted events, objects and attributes are excluded.

Values are validated and normalized. CIDRs are normalized to their network
address; qualified DNS names use lowercase ASCII IDNA; destination ports range
from 1 to 65535. Duplicate match tuples are removed across all supplied events,
and output order and ACL names are deterministic. Malformed composites are
skipped entirely. Invalid values cannot introduce directives into the file.

Domain ACLs use `-n` to prevent reverse DNS matching for IP-literal requests.
`dst` ACLs use Squid's destination address lookup when evaluating requests;
the exporter itself does not resolve names. Normal Squid destination resolution
and caching apply. `domain|ip` requires both the name and supplied address to
match, rather than blocking unrelated hosts sharing the address.

URL schemes and hosts are normalized, default ports are removed, and empty
paths become `/`. Fragments are removed because clients do not send them to the
proxy. Paths and queries retain their case. Regex metacharacters are escaped,
and anchors prevent host/path substring matches. URLs must be absolute HTTP(S),
without credentials, whitespace or control characters. Non-ASCII path/query
characters, quotes and backslashes must be percent-encoded; invalid percent
escapes are rejected. Other URL representations and application-specific
normalization may require different indicators.

For ordinary HTTPS CONNECT tunnels, Squid cannot see the encrypted URL path or
query. Exact HTTPS URL ACLs require visibility through separately configured TLS
inspection. They are not expanded into host-wide blocks. Domain, address and
port ACLs remain useful for CONNECT requests. The module does not configure TLS
inspection.

Unsupported types are skipped and counted. These include `ip-src|port` (Squid
has no equivalent client source-port ACL), relative `uri` values, hashes, email
addresses, MAC addresses, AS numbers and HTTP header indicators.

## Module API

Send a request to the misp-modules `/query` endpoint:

```json
{
  "module": "squid_export",
  "data": [
    {
      "Event": {
        "Attribute": [
          {"type": "domain", "value": "example.org", "to_ids": true},
          {"type": "ip-dst|port", "value": "192.0.2.1|443", "to_ids": true},
          {"type": "url", "value": "http://example.net/payload", "to_ids": false}
        ]
      }
    }
  ]
}
```

`data` also accepts a single event, a bare event without the `Event` wrapper, or
legacy exports with `Attribute`/`Object` beside `Event`. The module is
automatically discovered in the export modules directory and has no configuration
or credentials to set.

The response's `data` is base64-encoded file content. Decode it to obtain:

```squid
# MISP Squid export: IDS-marked proxy attributes
# Include before http_access allow rules; reserve the misp_squid_ ACL prefix.
acl misp_squid_1_1 dstdomain -n .example.org
http_access deny misp_squid_1_1
acl misp_squid_2_1 dst 192.0.2.1
acl misp_squid_2_2 port 443
http_access deny misp_squid_2_1 misp_squid_2_2
```

`summary.count` counts unique deny rules, rather than individual ACL definitions
or input attributes. `summary.skipped` counts non-IDS, deleted, unsupported and
malformed attributes; whole deleted events and objects are ignored before
attributes are inspected. `warnings` explains skipped data, integration ordering
and URL/port scope. Structurally invalid input returns an `error` without a file.
Empty events produce only comments, with no access directives.

## Integrating with Squid

Save the decoded fragment as `/etc/squid/misp.conf` and include it in your
existing Squid configuration **before any `http_access allow` rules that could
accept matching requests**:

```squid
include /etc/squid/misp.conf
```

Squid uses the first matching `http_access` rule. Reserve ACL names beginning
with `misp_squid_` for this single generated fragment, replacing it on subsequent
exports. Keep your existing access policy and an explicit final
`http_access deny all`. The fragment contains only deny actions and is not a
complete proxy access policy; adding a deny as the last rule without an explicit
default can change Squid's implicit default behavior.

Check the complete configuration before loading it:

```sh
squid -k parse -f /etc/squid/squid.conf
```

References: [Squid ACLs](https://www.squid-cache.org/Doc/config/acl/),
[http_access](https://www.squid-cache.org/Doc/config/http_access/).
