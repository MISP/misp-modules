# OpenBSD PF export

`pf_export` converts IDS-marked network attributes from MISP events and objects
into a UTF-8/ASCII `.conf` fragment containing OpenBSD PF `block drop quick` rules
by default, or `match log (all)` rules when logging mode is selected.
The exporter requires no additional Python packages and makes no network requests.
It does not load rules or change the firewall.

## Supported attributes

| MISP type | PF match |
| --- | --- |
| `ip-src` | Source IPv4/IPv6 address or CIDR network |
| `ip-dst` | Destination IPv4/IPv6 address or CIDR network |
| `ip-src\|port` | Source address/network **and source port**, TCP and UDP |
| `ip-dst\|port` | Destination address/network **and destination port**, TCP and UDP |
| `domain`, `hostname` | Source and destination addresses resolved from the exact name by PF |
| `domain\|ip` | Source and destination matching only the supplied IP/network; no DNS lookup |
| `hostname\|port` | Destination hostname and destination port, TCP and UDP |
| `port` | Destination port on **all addresses**, TCP and UDP |

`ip-src` and `ip-dst` refer to packet fields, not PF's `in`/`out` interface
directions. Rules apply in both interface directions. Literal addresses use
`inet` or `inet6`; DNS names leave the address family unspecified so PF can
expand both IPv4 and IPv6 results. Attributes containing a port retain that
constraint. Each object attribute is processed independently; separate IP and
port attributes are not joined into an inferred connection tuple.

Only attributes with `to_ids` set to `true`, `1`, `"true"` or `"1"` are included
(boolean strings are case-insensitive). Missing/false flags are excluded. There
is no option to export non-IDS attributes. Deleted events, objects and attributes
are excluded. Values are validated and normalized, and identical rules are
deduplicated across all supplied events. Output order is deterministic.

DNS values must be qualified names; IDNs are converted to ASCII IDNA. Wildcards,
unqualified interface-like names, scoped IPv6 addresses, PF expressions and
service names are rejected. Numeric ports range from 0 to 65535. CIDRs are
normalized to their network address. Malformed composites are skipped entirely.

PF resolves names **when the ruleset is loaded**. These rules do not inspect DNS
queries, TLS SNI, HTTP Host headers or subdomains, and do not automatically follow
later DNS changes. Unresolvable names can prevent a ruleset from loading, and
shared hosting addresses affect every service at that address. `domain|ip` uses
the supplied address rather than expanding the domain to additional addresses.
Standalone port attributes cover all hosts; mark them for IDS only when that
scope is intended. In logging mode the same matches are logged instead of
blocked. The API returns warnings for DNS and standalone-port rules.

PF cannot faithfully match URL paths, URIs, email addresses, HTTP headers,
certificate/file fingerprints, MAC addresses or AS numbers through these IP
filter rules. Those attributes are skipped and counted as unsupported, without
turning them into broader host blocks.

## Module API

Send a request to the misp-modules `/query` endpoint:

```json
{
  "module": "pf_export",
  "data": [
    {
      "Event": {
        "id": "42",
        "Attribute": [
          {"type": "ip-src", "value": "192.0.2.1", "to_ids": true},
          {"type": "ip-dst|port", "value": "2001:db8::1|443", "to_ids": true}
        ]
      }
    }
  ]
}
```

`data` also accepts a single event, a bare event without the `Event` wrapper,
or legacy exports with `Attribute`/`Object` beside `Event`. The module is
automatically discovered in the export modules directory.

### Rule mode

The `mode` export option accepts `block` (default) or `log`. It is advertised in
both the module configuration and the per-export `userConfig` fields. Omitted,
null or empty values use `block`; other values produce an error without a file.

| `config.mode` | Generated action | Effect |
| --- | --- | --- |
| `block` | `block drop quick` | Drop matching packets and stop evaluating rules |
| `log` | `match log (all)` | Log matches and continue evaluating the existing firewall policy |

To select logging mode, add this top-level field to the request above:

```json
"config": {"mode": "log"}
```

For example, the IDS-marked `ip-src` attribute then produces:

```pf
match log (all) inet from 192.0.2.1 to any
```

Logging mode preserves pass/block decisions: it does not add `pass` or `quick`.
Packets may still be blocked by the existing policy. PF's `log (all)` requests
logging of all packets for matching connections. Logs go to `pflog0` by default;
configure `pflogd` to retain them, or inspect them with `tcpdump -n -e -ttt -i pflog0`.

The response's `data` field is base64-encoded file content. Decode it to obtain:

```pf
# MISP OpenBSD PF export: IDS-marked network attributes
block drop quick inet from 192.0.2.1 to any
block drop quick inet6 proto { tcp, udp } from any to 2001:db8::1 port = 443
```

`summary.count` is the number of unique rules, not the number of attributes.
`summary.skipped` counts deleted, non-IDS, malformed and unsupported attributes;
entire deleted events and objects are ignored before attributes are inspected.
`warnings`, when present, explains skipped attributes and DNS/port scope.
Structurally invalid input produces an `error` response without a file.
Empty events produce a comment-only fragment.

## Integrating with PF

Save the decoded content as `/etc/pf.misp.conf`. Include the fragment in the
filtering section of your existing `/etc/pf.conf`, at the position where these
rules should apply:

```pf
include "/etc/pf.misp.conf"
```

Review the combined ruleset and check its syntax on OpenBSD before loading it:

```sh
pfctl -n -f /etc/pf.conf
```

The fragment is not a complete firewall policy. Earlier matching `quick` rules
can prevent blocking or logging rules from being reached, and existing state
entries can bypass newly loaded rules. Place the include with your site's rule
ordering in mind. Loading and state management remain the operator's responsibility.

References: [pf.conf(5)](https://man.openbsd.org/pf.conf),
[pfctl(8)](https://man.openbsd.org/pfctl).
