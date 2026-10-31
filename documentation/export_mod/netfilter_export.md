# Netfilter nftables export

`netfilter_export` converts IDS-marked network attributes from MISP events and
objects into an ASCII `.nft` fragment for an **existing chain in an `inet` table**.
It uses nftables, the current Linux netfilter interface, and requires no additional
Python packages. The module generates rules; it does not run `nft` or modify a firewall.

## Options

| Configuration | Default | Behavior |
| --- | --- | --- |
| `mode` | `block` | `block` emits `counter drop`; `log` emits `counter log prefix "MISP: " level info` |
| `resolve_dns` | `false` | Resolve DNS-only indicators to concrete IPv4/IPv6 addresses at export time |

Both options appear in module configuration and per-export `userConfig`. Missing,
null or empty `mode` uses `block`. `resolve_dns` accepts booleans, integers 0/1
and strings `true`/`false`/`1`/`0` (case-insensitive); missing, null or empty means
false. Invalid settings return an error without a file.

Logging is non-terminating: it adds no accept/drop verdict, so subsequent rules
and the existing chain policy decide what happens to the packet. Logs use the
kernel logging backend and the fixed prefix `MISP: `; inspect them through your
kernel log collector, for example `journalctl -k`. Rules include counters in both
modes. The exported logging rule has no rate limit; system logging configuration
can still limit or discard messages.

## Supported attributes

| MISP type | nftables match |
| --- | --- |
| `ip-src` | `ip saddr` / `ip6 saddr`: source address or CIDR network |
| `ip-dst` | `ip daddr` / `ip6 daddr`: destination address or CIDR network |
| `ip-src\|port` | Source address/network and TCP/UDP source port |
| `ip-dst\|port` | Destination address/network and TCP/UDP destination port |
| `domain\|ip` | Supplied address/network in both source and destination; never resolves the name |
| `domain`, `hostname` | Resolved addresses in both source and destination; requires `resolve_dns` |
| `hostname\|port` | Resolved destination addresses and TCP/UDP destination port; requires `resolve_dns` |
| `port` | TCP/UDP destination port on **all IPv4 and IPv6 addresses** |
| `mac-address` | Ethernet source MAC address, normalized to lowercase colon-separated EUI-48 |

Source and destination refer to packet fields. The chosen chain hooks determine
whether rules see local inbound, local outbound or forwarded traffic. Port rules
use `meta l4proto { tcp, udp } th sport/dport`, including IPv6 packets with
extension headers; use an nftables/kernel version supporting these expressions.
Separate IP and port attributes inside objects are processed independently,
without inferring a connection tuple between them.

Only attributes with `to_ids` set to `true`, `1`, `"true"` or `"1"` are included
(boolean strings are case-insensitive). Missing/false flags are excluded. Deleted
events, objects and attributes are excluded. Addresses and networks are normalized;
numeric ports range from 0 to 65535. Identical rules are deduplicated across all
supplied events and objects. Order is deterministic for a given set of resolved
addresses. Malformed values and composites are skipped entirely.

MAC matching requires an Ethernet header, usually on inbound/forwarded Ethernet
traffic. It sees the source on the observed link, not an original host's MAC
across routers, and may not match locally generated output. Colon- and
hyphen-separated 48-bit addresses are accepted; EUI-64 addresses are unsupported.
Place these rules in chains where Ethernet headers are available. Standalone
ports cover all hosts; mark them for IDS only when that scope is intended.

### DNS-only indicators

By default the exporter performs **no DNS lookups**. It skips `domain`, `hostname`
and `hostname|port` with the `DNS resolution disabled` count. To include them,
explicitly set `"resolve_dns": true`.

Names must be qualified DNS names; IDNs are converted to ASCII IDNA. Wildcards,
unqualified names, scoped IPv6 addresses and injected nftables expressions are
rejected. Opt-in resolution uses the server's system resolver, querying each
normalized fully qualified name at most once per export. All usable IPv4 and
IPv6 results are expanded into numeric rules. Names with only IPv4 or only IPv6
results work. Unresolvable names are skipped with warnings, preserving rules for
the remaining indicators. Resolver timeouts follow the system configuration.

These are **export-time address snapshots**. They do not match DNS query payloads,
subdomains, HTTP Host headers or TLS SNI, and do not follow DNS changes or TTLs.
Re-export and replace the managed rules when refreshing addresses. Blocking a
shared address also affects other services using that address. A `domain|ip`
attribute always uses only its supplied address, regardless of `resolve_dns`.

URL paths, URIs, AS numbers, email addresses, HTTP headers, file/certificate
fingerprints and other unsupported types are counted and skipped without
turning them into broader network matches.

## Module API

Send this JSON to the misp-modules `/query` endpoint:

```json
{
  "module": "netfilter_export",
  "config": {"mode": "block", "resolve_dns": false},
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
or legacy exports with `Attribute`/`Object` beside `Event`. Object attributes are
included. The service discovers the module automatically.

Decode the response's base64 `data` field to obtain:

```nft
# MISP netfilter nftables export: include inside an inet-family chain
ip saddr 192.0.2.1 counter drop
ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 443 counter drop
```

Selecting `"mode": "log"` changes the same matches to:

```nft
ip saddr 192.0.2.1 counter log prefix "MISP: " level info
ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 443 counter log prefix "MISP: " level info
```

`summary.count` counts unique rules, not attributes. `summary.skipped` counts
deleted, non-IDS, unsupported, malformed, DNS-disabled and unresolved-DNS
attributes. Entire deleted events/objects are ignored before inspecting their
attributes. `warnings` describes skips, DNS snapshots and port/MAC scope.
Invalid request structure produces an `error` without a file. Empty input
produces a comment-only fragment.

## Integration

The exported file is a **chain body**, not a standalone ruleset or an iptables
script. Save it, for example, as `/etc/nftables/misp.nft`. Add an include inside a
regular chain in your existing `inet` table. This schematic excerpt shows the
placement; retain your existing table contents, base chains and policies:

```nft
table inet filter {
    chain misp {
        include "/etc/nftables/misp.nft"
    }
    # Existing base chains and site rules belong here.
}
```

Add `jump misp` at the appropriate point inside your existing input, forward
and/or output chains in the **same table**. Rule ordering matters: an earlier
accept, drop, return or established-connection shortcut can prevent a jump from
being reached. Logging rules fall through and return to the caller when the
regular chain ends. Flowtable offload can also bypass later packet inspection.

Validate the **combined** configuration with appropriate privileges before
using your normal ruleset deployment process:

```sh
nft --check --file /etc/nftables.conf
```

The module emits no hooks, chain policies, flush or delete commands. Changing the
file alone does not update kernel rules. Replace or reload the managed chain
through your existing configuration process; repeatedly appending fragments
retains duplicate and stale rules. Rule deployment remains the operator's responsibility.

References: [nftables project](https://netfilter.org/projects/nftables/),
[nft(8)](https://www.netfilter.org/projects/nftables/manpage.html).
