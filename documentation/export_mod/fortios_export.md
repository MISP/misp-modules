# Fortinet FortiOS ACL export

`fortios_export` targets **FortiOS 7.4+ unified firewall policies**, with IPv4
`srcaddr`/`dstaddr` and IPv6 `srcaddr6`/`dstaddr6`. It emits required address and
custom service objects before each policy. It does not emit legacy `policy6`
syntax. See the [shared ACL guide](network_acl_exports.md) for supported attributes,
DNS behavior and the module API.

| Setting | Default |
| --- | --- |
| `mode` | `block` (`deny`); `log` uses `accept` |
| `name_prefix` | `MISP-IOC` (**maximum 18 characters**) |
| `resolve_dns` | `false` |
| `srcintf` | `any` |
| `dstintf` | `any` |
| `start_policy_id` | `10000` |

Interface/zone settings are validated single tokens. `start_policy_id` accepts
a decimal string or integer in 1-4294967294; booleans are rejected. If the last
generated ID exceeds that limit, the request returns an error without a file.

**Reserve a dedicated policy ID range in the selected VDOM.** Policies use
`edit <start_policy_id + index>`, which modifies any existing policy with that ID.
IDs follow sorted matches, so changing indicators can reassign IDs. A managed
prefix identifies names; it does not prevent numeric ID collisions. Remove stale
policies and supporting objects when refreshing, and place replacements before
relevant existing decisions. The fragment does not select a VDOM or move policies.

IPv4 objects use normalized networks and subnet masks. IPv6 objects use
`config firewall address6` and `set ip6 <prefix>`. Each rule includes an explicit
managed `/0` object for its unrestricted endpoint; no built-in all-address
object is assumed. The policy sets only its own address family and unsets the
other family's address fields so refreshing an ID cannot retain an old family.

Port rules use separate TCP/UDP custom services. Destination constraints use
`set tcp-portrange 443` / `set udp-portrange 443`. Source constraints use
`set tcp-portrange 1-65535:443` / `set udp-portrange 1-65535:443`, where the
destination range precedes the source port. Port zero is skipped; source-port
services cover destination ports 1-65535. Address-only policies use service `ALL`.

Every policy sets the requested interfaces, schedule `always`, its action, and
`logtraffic all`. No NAT, security profiles or routing configuration is generated.
**Logging mode accepts traffic** and can bypass later denies or inspection policy;
use it only where that verdict is intended. Logging destinations and security
inspection requirements must be configured separately.

Policy names are limited to 35 characters: at most 18 prefix characters, a
hyphen and a 16-character match digest. Object names append `-addr`, `-any` or
`-svc`. Use a dedicated managed namespace and ID range.

Reference: [FortiOS 7.4 firewall policy CLI](https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/333889629/config-firewall-policy).
