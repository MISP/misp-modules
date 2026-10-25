# Cisco ASA ACL export

`cisco_asa_export` targets ASA **9.x unified IPv4/IPv6 extended ACLs**. This is
separate from the [IOS/IOS-XE exporter](cisco_acl_export.md) and the Firepower
Management Center exporter. See the [shared ACL guide](network_acl_exports.md)
for supported attributes, DNS behavior and API requests.

| Setting | Default |
| --- | --- |
| `mode` | `block` (`deny`); `log` uses `permit ... log` |
| `name_prefix` | `MISP-IOC` (maximum 27 characters) |
| `resolve_dns` | `false` |

Both IPv4 and IPv6 entries use the same ACL name, exactly `name_prefix` (default
`MISP-IOC`). ASA permits only one extended ACL per interface and direction, so
the two families must share a unified ACL. IPv4 networks use **subnet masks**,
hosts use `host`, and unrestricted endpoints use `any4`/`any6` to retain family
scope. IPv6 networks use prefix notation. Port constraints stay on their source
or destination endpoint; TCP and UDP get separate entries. Port zero is supported.

Example source TCP/443 and destination IPv6 UDP/53 entries:

```text
access-list MISP-IOC extended deny tcp 192.0.2.0 255.255.255.0 eq 443 any4
access-list MISP-IOC extended deny udp any6 host 2001:db8::1 eq 53
```

**Logging mode permits matching traffic** and stops ACL evaluation. It can
bypass later denies. It does not implement nonterminating logging.

ASA ACLs have an implicit deny. Merge entries into existing ACLs and preserve
their final decisions. Unnumbered `access-list` commands normally append entries;
explicitly position them before relevant existing permits or denies. Applying
a new block-only ACL can deny unrelated traffic too. Remove stale managed ACEs
when refreshing; identical and changed entries may be handled differently by
the device. No `access-group`, catch-all permit, global configuration command
or save command is generated. Review ASA real-address/NAT matching requirements
for the selected interfaces and deployment.

Reference: [ASA access-list commands](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html).
