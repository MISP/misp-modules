# BPF capture filter export

`bpf_export` converts IDS-marked MISP event and object network attributes into a
single libpcap capture expression, suitable for tcpdump and other tools accepting
[pcap-filter syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html).
No additional Python dependency is required.

## Supported attributes

| MISP type | Capture match |
| --- | --- |
| `ip-src`, `ip-dst` | Source or destination IPv4/IPv6 address or CIDR network |
| `ip-src\|port`, `ip-dst\|port` | Source address and source port, or destination address and destination port, for TCP/UDP |
| `domain`, `hostname` | Either endpoint of the exact name, resolved by libpcap |
| `domain\|ip` | Either endpoint of the supplied IP/network, without resolving the domain |
| `hostname\|port` | Destination hostname and destination port for TCP/UDP |
| `port` | Destination port for TCP/UDP, on all addresses |
| `mac-address` | Either Ethernet endpoint |

Only `to_ids` attributes are exported (`true`, `1`, `"true"`, `"1"`, with
case-insensitive boolean strings). Missing/false flags and deleted events,
objects and attributes are excluded. Standard `Event` envelopes, bare events,
legacy exports with collections beside `Event`, and collections of events are
accepted. Each object attribute is handled independently; separate IP and port
attributes are not combined into an inferred connection.

Addresses and networks are normalized, numeric ports must be 0–65535, MACs are
normalized to colon-separated hexadecimal, and qualified DNS names are validated
and converted to ASCII IDNA. Scoped IPv6, wildcards, service names, malformed
values and injected filter syntax are skipped. URL paths, hashes, email addresses
and other unsupported types are counted and skipped without broadening them.

Each match is parenthesized and joined with `or`. Identical expressions are
deduplicated and sorted. The result selects packets matching **any** exported
indicator; it is capture filter source, rather than compiled BPF bytecode.

## API and usage

Submit to the misp-modules `/query` endpoint:

```json
{
  "module": "bpf_export",
  "data": [{"Event": {"Attribute": [
    {"type": "ip-src", "value": "192.0.2.1", "to_ids": true},
    {"type": "ip-dst|port", "value": "2001:db8::1|443", "to_ids": true}
  ]}}]
}
```

Decode the response's base64 `data` field and save it as `misp.bpf`:

```text
(ip6 dst host 2001:db8::1 and (tcp or udp) and dst port 443) or
(ip src host 192.0.2.1)
```

Load the file using:

```sh
tcpdump -nn -i eth0 -F misp.bpf
tcpdump -nn -r input.pcap -F misp.bpf -w matched.pcap
# Check compilation for the intended capture link type:
tcpdump -d -r input.pcap -F misp.bpf
```

`summary.count` counts unique expressions; `summary.skipped` counts excluded
attributes by reason. Deleted events and objects are ignored as a whole.
`warnings` explains skipped values and DNS, port or MAC scope. Invalid request
structure produces an `error` without a file. If no usable indicators remain,
the module returns an error and summary **without file data**, because an empty
filter file could start an unfiltered capture.

DNS names are resolved by libpcap **at compilation time**, without DNS requests
from the exporter. Unresolvable names can prevent compilation. This is a snapshot
of resolved addresses; it does not inspect DNS queries, TLS SNI, HTTP Host headers
or subdomains. Shared hosting addresses can select unrelated traffic. Standalone
ports cover all addresses. MAC filters depend on capture link type and are not
appropriate for every interface (for example Linux cooked captures).

Port matches follow libpcap's protocol parsing and fragmentation limitations;
non-initial fragments generally do not expose ports, and IPv6 extension headers
can prevent transport matches. VLAN encapsulation and other link-layer wrappers
are not automatically expanded. Validate the filter with representative traffic
and the intended interface/link type. Very large exports may exceed the target
platform's BPF instruction limits.
