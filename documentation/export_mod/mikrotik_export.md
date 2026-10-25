# MikroTik RouterOS ACL export

`mikrotik_export` produces RouterOS v7 `/ip firewall filter add` and
`/ipv6 firewall filter add` commands. See the [shared ACL guide](network_acl_exports.md)
for supported attributes, API requests, DNS behavior and name validation.

| Setting | Default |
| --- | --- |
| `mode` | `block` (`action=drop`); `log` uses `action=log` |
| `name_prefix` | `MISP-IOC` (maximum 27 characters) |
| `resolve_dns` | `false` |
| `chain` | `forward`; also accepts `input` or `output` |

Each command explicitly specifies source/destination prefixes and address family.
Port matches use separate TCP/UDP rules with `src-port` or `dst-port`. Port zero
is supported. Managed comments contain the prefix and a digest of the match.

Example source TCP/443 rule (the UDP rule is emitted separately):

```text
/ip firewall filter add chain=forward action=drop src-address=192.0.2.1/32 dst-address=0.0.0.0/0 protocol=tcp src-port=443 comment="<managed-name>"
```

`action=log` logs then continues to the next rule. It does not change later
policy decisions. Logging rules include a `log-prefix` based on `name_prefix`.
The device's logging configuration and rate limits still apply.

`add` appends rules. Place generated entries **before established/related accepts,
FastTrack and other terminal decisions** if they must see those packets. Existing
FastTrack/session state can still bypass processing until addressed through the
normal deployment process. Choose `input` for traffic to the router, `output`
for locally generated traffic, or `forward` for transit traffic.

Imports do not remove or update old rules. Use the reserved comment prefix to
identify managed entries, remove stale entries and position replacements using
configuration management. Repeated imports can create duplicates. No removal,
movement, chain binding, catch-all accept or system configuration is generated.

Reference: [RouterOS firewall filters](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter).
