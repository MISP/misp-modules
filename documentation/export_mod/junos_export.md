# Juniper Junos ACL export

`junos_export` produces Junos **stateless firewall filter** terms in `set` format,
using `family inet` and `family inet6`. It does not generate SRX zone-based
security policies or address-book objects. See the [shared ACL guide](network_acl_exports.md)
for supported attributes, configuration defaults, API requests and DNS behavior.

| Setting | Default |
| --- | --- |
| `mode` | `block` (`discard`); `log` uses `log` and `next term` |
| `name_prefix` | `MISP-IOC` (maximum 27 characters) |
| `resolve_dns` | `false` |

Filters are named `<prefix>-V4` and `<prefix>-V6`; term names include the prefix
and a digest of the normalized match. Only populated families are emitted.
Both source and destination networks are explicit. For port matches, IPv4 uses
`from protocol tcp/udp`; IPv6 uses `from next-header tcp/udp`, with the appropriate
`source-port` or `destination-port`. TCP and UDP have separate terms. Port zero
is representable. Device support for IPv6 extension headers and noninitial
fragments must be reviewed on the target platform.

For a destination TCP/443 match, a term includes commands equivalent to:

```text
set firewall family inet6 filter MISP-IOC-V6 term <managed-name> from source-address ::/0
set firewall family inet6 filter MISP-IOC-V6 term <managed-name> from destination-address 2001:db8::1/128
set firewall family inet6 filter MISP-IOC-V6 term <managed-name> from next-header tcp
set firewall family inet6 filter MISP-IOC-V6 term <managed-name> from destination-port 443
set firewall family inet6 filter MISP-IOC-V6 term <managed-name> then discard
```

Logging mode replaces `then discard` with `then log` and `then next term`.
It preserves evaluation of subsequent policy. Retrieve logs using the platform's
firewall logging facilities; a syslog forwarding action is not generated.

**Filters have an implicit discard.** Merge terms into existing filters, retain
their final terms, and insert generated terms before relevant accept/discard
decisions. Appending terms after a terminal catch-all makes them unreachable.
No catch-all accept, interface attachment, filter deletion or commit is emitted.
Remove stale terms through configuration management before refreshing the IOC set.

Reference: [Junos firewall filters](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-overview.html).
