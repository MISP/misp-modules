# Palo Alto PAN-OS ACL export

`panos_export` produces local PAN-OS security policy `set` commands and the custom
TCP/UDP services needed for port constraints. See the [shared ACL guide](network_acl_exports.md)
for supported attributes, DNS behavior, API requests, name validation and refresh semantics.

| Setting | Default |
| --- | --- |
| `mode` | `block` (`drop`); `log` uses `allow` |
| `name_prefix` | `MISP-IOC` (maximum 27 characters) |
| `resolve_dns` | `false` |
| `from_zone` | `any` |
| `to_zone` | `any` |

The output uses `set rulebase security rules` in the selected local virtual system.
It does not target Panorama device-group pre/post rulebases. Select the intended
vsys and configuration context yourself. Rules set both source and destination
prefixes, zones, `application any`, their service, action, and `log-end yes`.
Address-only rules use `service any`; port rules refer to generated services.

For `ip-src|port=192.0.2.1|443`, two service definitions include:

```text
set service <managed-name>-svc protocol tcp port 1-65535 source-port 443
set service <other-managed-name>-svc protocol udp port 1-65535 source-port 443
```

Each corresponding rule matches source `192.0.2.1/32`, destination `0.0.0.0/0`,
and the appropriate service. Destination-port services set the destination port
directly. IPv6 uses explicit IPv6 prefixes, including `::/0`, to retain family
scope. Port zero is skipped; source-port services cover destination ports 1-65535.

**Logging mode allows traffic** and can bypass later deny rules. It is not a
passive monitoring rule. Both modes request session-end logging; log forwarding
profiles and device logging configuration remain the administrator's responsibility.

New rules can be appended after existing permits. Place them deliberately in
the rulebase before relevant decisions, remove stale managed rules and services,
and review the candidate configuration before committing. The export contains
no `configure`, `move` or `commit` commands.

Reference: [PAN-OS CLI quick start](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start).
