# Cisco IOS ACL export

`cisco_acl_export` generates Cisco IOS/IOS-XE named IPv4 extended and IPv6 ACL
configuration fragments from IDS-marked MISP event and object attributes. It
requires no additional Python packages and does not connect to a device or apply
configuration. This module targets IOS/IOS-XE IP ACLs. The separate fireSIGHT
exporter targets Cisco Firepower Management Center.

## Options

| Configuration | Default | Behavior |
| --- | --- | --- |
| `mode` | `block` | `block` emits `deny`; `log` emits **`permit ... log`** |
| `acl_name` | `MISP-IOC` | Prefix for the generated names, adding `-V4` and `-V6` |
| `resolve_dns` | `false` | Resolve DNS-only attributes to address snapshots at export time |

Options are advertised in module configuration and per-export `userConfig`.
Missing, null or empty `mode` and `acl_name` use their defaults. Names must start
with an ASCII letter and contain 1-27 ASCII letters, digits, underscores or
hyphens. The three-character `-V4`/`-V6` suffix keeps generated names within
IOS XE's 30-character named IPv4 ACL limit. Numeric-only names and CLI expressions
are rejected. `resolve_dns` accepts booleans, integers 0/1 and strings
`true`/`false`/`1`/`0`, ignoring case;
missing, null or empty means false. Invalid settings return an error without a file.

### Logging and policy semantics

**Cisco ACLs are first-match.** Logging mode uses `permit ... log`, which permits
matching traffic and stops evaluating that ACL. It can bypass a later deny; it
does not provide nftables-style non-terminating logging. The download comments,
API warnings and export option label explicitly identify this behavior. Use it
only where permitting those matches is the intended policy.

ACLs end in an implicit deny. The exporter adds **no final `permit ip any any` or
`permit ipv6 any any`**, so it does not replace your site's final policy decision.
Merge the entries into an existing ACL and preserve its other rules. Applying a
new deny-only ACL directly would deny other traffic at its implicit end too.
IPv6 platforms may also have implicit neighbor-discovery entries; retain the
control-plane and neighbor-discovery rules required by your platform.

The `log` keyword requests device ACL logging. Log aggregation, rate limits,
hardware forwarding and device logging settings affect the resulting messages;
this is not a guarantee of one syslog message per packet.

## Supported attributes

| MISP type | ACL match |
| --- | --- |
| `ip-src` | Source IPv4/IPv6 address or CIDR network |
| `ip-dst` | Destination IPv4/IPv6 address or CIDR network |
| `ip-src\|port` | Source address/network **and source port**, separate TCP and UDP entries |
| `ip-dst\|port` | Destination address/network **and destination port**, separate TCP and UDP entries |
| `domain\|ip` | Supplied IP/network as source and destination; no name lookup |
| `domain`, `hostname` | Resolved addresses as source and destination; requires `resolve_dns` |
| `hostname\|port` | Resolved destination addresses and TCP/UDP destination port; requires `resolve_dns` |
| `port` | TCP/UDP destination port on **all IPv4 and IPv6 addresses** |

IPv4 hosts use `host`, networks use normalized addresses with inverse wildcard
masks, and `/0` becomes `any`. IPv6 hosts use `host`, networks use normalized
prefixes, and `/0` becomes `any`. Host addresses and equivalent `/32` or `/128`
values deduplicate. Numeric ports range from 0 to 65535. Port entries match
inspectable transport headers; device-specific fragment handling still applies.

Source/destination describe packet fields, not interface directions. Separate IP
and port attributes in an object are processed independently, without inferring
a connection tuple. Standalone IDS-marked ports cover all hosts in both families.

Only `to_ids` attributes are included. Accepted true representations are `true`,
`1`, `"true"` and `"1"` (boolean strings are case-insensitive); missing/false flags
are excluded. Deleted events, objects and attributes are excluded. Identical
entries are deduplicated across supplied events, with deterministic ordering
for a given set of resolved addresses. Malformed composites are skipped entirely.

MAC/EUI-64 addresses, AS numbers, URL paths, HTTP headers, email addresses,
certificate/file fingerprints and other unsupported attributes are counted and
skipped. A separate MAC ACL is outside the scope of these layer-three IP ACLs.
Unsupported values are not converted into broader host rules.

### DNS-only indicators

The default performs no DNS lookups. `domain`, `hostname` and `hostname|port`
are skipped with the `DNS resolution disabled` count until `resolve_dns` is
explicitly enabled. Names must be qualified; IDNs are normalized to ASCII IDNA.
Wildcards, unqualified names, scoped IPv6 and injected CLI syntax are rejected.

Opt-in resolution uses the server's system resolver. Each normalized fully
qualified name is resolved at most once per export, including failed lookups.
All usable IPv4 and IPv6 answers become numeric host entries; single-family
answers work too. Failed lookups are counted as `unresolved DNS` and do not
discard other indicators. Timeouts follow the system resolver configuration.

The output contains **export-time address snapshots**, not DNS query, HTTP Host,
TLS SNI or subdomain matches. It does not track TTLs or DNS changes. Re-export and
replace managed entries to refresh addresses. Shared addresses affect other
services using them. `domain|ip` always uses only its supplied IP/network and
never expands the domain, even with DNS resolution enabled.

## Module API

Send this request to the misp-modules `/query` endpoint:

```json
{
  "module": "cisco_acl_export",
  "config": {"mode": "block", "acl_name": "MISP-IOC", "resolve_dns": false},
  "data": [
    {
      "Event": {
        "id": "42",
        "Attribute": [
          {"type": "ip-src", "value": "192.0.2.7/24", "to_ids": true},
          {"type": "ip-dst|port", "value": "2001:db8::1|443", "to_ids": true}
        ]
      }
    }
  ]
}
```

`data` also accepts a single event, bare events without the `Event` wrapper, and
legacy exports with `Attribute`/`Object` beside `Event`. Object attributes are
included. The service discovers the module automatically.

The response's base64 `data` field decodes to a `.cfg` file:

```text
! MISP Cisco IOS/IOS-XE ACL export: IDS-marked network attributes
! ACL fragments have an implicit deny; merge entries into existing policy and retain its final rules.
ip access-list extended MISP-IOC-V4
 deny ip 192.0.2.0 0.0.0.255 any
exit
ipv6 access-list MISP-IOC-V6
 deny tcp any host 2001:db8::1 eq 443
 deny udp any host 2001:db8::1 eq 443
exit
```

With `"mode": "log"`, each deny becomes a permit with `log`, for example:

```text
 permit tcp any host 2001:db8::1 eq 443 log
```

An additional comment warns that logging mode permits matching traffic. Only
families with entries get an ACL section; empty input produces comments without
creating an empty ACL. `summary.count` counts unique ACEs, excluding context
commands and comments. `summary.skipped` counts deleted, non-IDS, malformed,
unsupported, DNS-disabled and unresolved-DNS attributes. Entire deleted events
and objects are ignored before inspecting their attributes. `warnings` explains
skips, implicit deny, logging semantics, DNS snapshots and standalone-port scope.
Structurally invalid requests return an `error` without a file.

## Integration and validation

These are **reviewable fragments**, not a complete firewall policy. The context
headers identify named ACLs and `exit` leaves their configuration submode. The
file does not enter global configuration mode, apply ACLs to interfaces, delete
ACLs, add a catch-all permit, or save configuration. No device credentials are needed.

Choose names for the existing ACLs you intend to maintain, or merge their entries
using your configuration management process. IOS commonly appends unnumbered
entries when pasted into an existing ACL. A broad earlier permit/deny can make
new entries unreachable, so explicitly place or resequence entries before the
relevant existing decisions. The exporter does not assign sequence numbers or
remove stale entries; repeated append-only imports leave old rules in place.

Review each address family independently, retain the site's final policy and
IPv6 control-plane requirements, and validate the configuration on the intended
IOS/IOS-XE platform before applying it through your normal deployment process.
Tests cover generated text and the module API; no live Cisco device validation
was available in the development environment.

References: [IPv4 access lists](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-create-ip-apply-0.html),
[IPv6 access lists](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_ip6-acls-xe.html),
[named ACL limits](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-named.html).
