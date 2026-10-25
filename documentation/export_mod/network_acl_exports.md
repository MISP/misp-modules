# Network ACL exporters

These exporters turn IDS-marked MISP event and object attributes into firewall
configuration fragments. They require no additional dependencies, device access
or credentials. They do not apply, bind, commit or save device configuration.

| Module | Target | Block mode | Log mode |
| --- | --- | --- | --- |
| [`panos_export`](panos_export.md) | PAN-OS local security policy | `drop`, log at session end | `allow`, log at session end |
| [`junos_export`](junos_export.md) | Junos stateless `inet`/`inet6` filters | `discard` | `log` and `next term` |
| [`fortios_export`](fortios_export.md) | FortiOS 7.4+ unified firewall policies | `deny`, log all | `accept`, log all |
| [`cisco_asa_export`](cisco_asa_export.md) | Cisco ASA 9.x extended ACLs | `deny` | `permit ... log` |
| [`mikrotik_export`](mikrotik_export.md) | RouterOS v7 firewall filters | `drop` | `action=log`, continue |

Existing exporters cover [Cisco IOS/IOS-XE](cisco_acl_export.md), Cisco
Firepower Management Center (`cisco_firesight_manager_ACL_rule_export`),
[OpenBSD PF](pf_export.md) and [nftables](netfilter_export.md).
These formats are distinct; for example, ASA uses IPv4 subnet masks while IOS
extended ACLs use inverse wildcard masks.

## Shared configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `block` | `block` or `log`; semantics depend on the vendor above |
| `name_prefix` | `MISP-IOC` | Prefix for managed rules and supporting objects |
| `resolve_dns` | `false` | Resolve DNS-only attributes to numeric address snapshots |

Missing, null and empty settings use defaults. Names start with an ASCII letter
and contain ASCII letters, digits, `_` or `-`. The maximum prefix length is 27,
or **18 for FortiOS** to respect its 35-character policy-name limit. Zone and
interface options follow the same token syntax, with a 27-character maximum;
quoted names, spaces and CLI expressions are unsupported.

Boolean flags accept booleans, integers 0/1, and case-insensitive strings
`true`/`false`/`1`/`0`. Missing, null and empty flags mean false. Invalid options
or request structure return an `error` without a download.

## Supported attributes

| MISP type | Match |
| --- | --- |
| `ip-src` | Source IPv4/IPv6 address or CIDR network |
| `ip-dst` | Destination IPv4/IPv6 address or CIDR network |
| `ip-src\|port` | Source address/network **and source port**, TCP and UDP separately |
| `ip-dst\|port` | Destination address/network **and destination port**, TCP and UDP separately |
| `domain\|ip` | Supplied address/network as source and destination; no DNS lookup |
| `domain`, `hostname` | Resolved addresses as source and destination, when DNS is enabled |
| `hostname\|port` | Resolved destination addresses **and destination port**, when DNS is enabled |
| `port` | TCP/UDP destination port on all IPv4 and IPv6 addresses |

Only attributes marked `to_ids` are included. Deleted events, objects and
attributes are excluded. Event attributes and object attributes are processed
independently; the exporter does not infer relationships between separate IP
and port attributes in an object. Source/destination refer to packet fields,
not interface or traffic directions.

Networks normalize their host bits. Equivalent hosts and `/32` or `/128` values
deduplicate, as do equivalent IPv6 spellings. CIDR `/0` remains specific to its
address family. Port-bearing attributes expand into separate TCP and UDP matches.
Ports are numeric, 0-65535, but PAN-OS and FortiOS skip port zero explicitly
because their service definitions require 1-65535. For source-port services on
these two platforms, the otherwise unrestricted destination port range is
1-65535. Traffic to destination port zero is outside these service matches.

MAC addresses, URLs, AS numbers, hashes, email and other unsupported types are
counted and skipped. Invalid composites are skipped in full. Unsupported
constraints are never dropped to produce a broader address-only rule.

## DNS behavior

DNS-only types are skipped by default. Enabling `resolve_dns` uses the server's
system resolver. Qualified names are validated and IDNs converted to ASCII IDNA.
Each normalized name is resolved once per export, including failed resolutions.
All usable A and AAAA answers become host matches. Scoped IPv6, wildcards,
unqualified names and injected CLI syntax are rejected. Unresolved names are
counted and do not discard other indicators. Resolver timeouts follow the host's
system resolver configuration.

These are export-time snapshots. They do not track TTLs, match DNS queries,
TLS SNI or HTTP Host, or automatically refresh with DNS changes. Shared hosting
addresses can affect other services. `domain|ip` always uses its supplied IP
and never resolves the name.

## API example

The modules are discovered automatically and advertise their settings through
`/modules`, including per-export `userConfig` fields. Send a request to `/query`:

```json
{
  "module": "panos_export",
  "config": {
    "mode": "block",
    "name_prefix": "MISP-IOC",
    "resolve_dns": false,
    "from_zone": "Trust",
    "to_zone": "Untrust"
  },
  "data": [{
    "Event": {
      "Attribute": [
        {"type": "ip-src", "value": "192.0.2.7/24", "to_ids": true},
        {"type": "ip-dst|port", "value": "2001:db8::1|443", "to_ids": true}
      ]
    }
  }]
}
```

`data` accepts a single event or event list, bare events, `Event` wrappers, and
legacy exports with `Attribute`/`Object` beside `Event`. The response contains:

- `data`: base64-encoded ASCII `.cfg` fragment.
- `response`: an empty list, following the existing export API.
- `summary.count`: unique packet matches/rules, excluding supporting objects,
  context commands and comments. Each address/port match counts twice for TCP/UDP.
- `summary.skipped`: attribute counts by reason: `deleted`, `non-IDS`,
  `unsupported`, `malformed`, `DNS resolution disabled`, `unresolved DNS`, or
  `unsupported port zero`. Entire deleted events and objects are ignored.
- `warnings`: skipped counts, integration requirements and relevant DNS/port/log
  semantics. The same warnings appear as comments in the download.

Empty input emits comments without creating policies, filters or objects.
Rule order is deterministic. PAN-OS, Junos, FortiOS and RouterOS managed rule
names/comments use the prefix and a 16-character SHA-256 digest of the normalized
packet match. FortiOS numeric IDs are assigned separately. ASA uses `name_prefix`
directly as one unified ACL name for IPv4 and IPv6 entries. Changing the verdict
mode retains the same managed names.

## Policy integration

Review fragments against the intended platform release and site policy. Merge
entries before relevant existing terminal decisions and retain the site's final
rules. ASA ACLs and Junos filters have implicit deny/discard behavior; attaching
a new block-only list/filter can therefore also deny unrelated traffic.
PAN-OS, ASA and FortiOS logging mode **permits matching traffic and stops policy
evaluation**, which can bypass later deny rules. Junos and RouterOS logging
continues evaluation and relies on later rules for the verdict.

Reserve a unique managed prefix and, for FortiOS, a dedicated numeric policy ID
range. Imports do not remove stale entries. PAN-OS/Junos set commands can update
existing managed names; ASA and RouterOS append entries; FortiOS `edit` modifies
existing IDs. Refresh through configuration management that removes stale rules
and objects and explicitly places the replacement fragment. No exporter adds a
catch-all permit or changes interface bindings, routing, NAT or management access.

Packet logging is subject to device settings, buffering, aggregation and rate
limits. Stateful policies normally evaluate session initiation; existing sessions,
FastTrack, hardware offload, fragments and IPv6 extension headers can affect
matches and logging. Preserve required control-plane and neighbor-discovery rules.

Tests validate generated syntax, constraints, input handling and the HTTP module
API. No live firewall or vendor CLI parser validation was available.
