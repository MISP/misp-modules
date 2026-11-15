# PCAP Import

Imports base64-encoded PCAP or PCAPNG captures using offline TShark dissection.
The module retains HTTP file and SMTP message reconstruction, email attachments
and body URLs, DNS observations, IPv4/IPv6 addresses, HTTP metadata and TLS SNI.
It does not capture traffic, resolve names, fetch URLs or decrypt TLS.

## Capture and flow provenance

Each result includes a standard pcap-metadata object describing the exact
uploaded bytes: MD5, SHA-1, SHA-256, size, format, packet count and observed time
range. The optional request filename is retained; otherwise the name defaults
to capture.pcap or capture.pcapng. The capture is identified by hashes rather
than attached to the result again. No capture device, application or filter
metadata is invented.

Each unambiguous TCP or UDP stream becomes a standard network-connection
object. Its identity is scoped by the capture SHA-256, transport and TShark
stream index; stream 0 in two different captures is not the same flow.
The object retains source/destination IPs and ports, IP version, transport,
observed application protocols, directional packet counts and first/last
packet times.

Endpoint orientation follows the first observed packet. It does not assert
which endpoint initiated the connection, or which is the client/server.
Reverse-direction packets remain in the same stream. Retransmissions count
as observed packets. Packets whose direction cannot be assigned are counted
separately as unoriented_packets in the flow comment.

Flow comments contain JSON with capture_sha256, transport, stream_id,
orientation and a packets list of frame_number/time_epoch records. The
time_epoch strings retain original decimal precision, including nanoseconds.
Packets with multiple nested stream candidates or insufficient context remain
in the pcap-metadata text attribute's unassigned_packets list, including any
reported stream IDs. Ambiguous flattened endpoint fields are not paired by
guessing.

## Network observations and intervals

Event-level network attributes remain deduplicated by type/value. Each now
has first_seen and last_seen spanning the packets in which TShark exposes that
field. Capture and flow objects reference these attributes; reference comments
contain JSON listing the contributing frame numbers and field names. The flow
packet records retain the corresponding exact timestamps, so a value shared
by several streams does not lose its stream context.

A DNS answer address remains an observation within its DNS flow. It is not
substituted for that flow's actual destination endpoint.

The graph uses standard MISP references:

- Capture metadata contains flow objects and observed network attributes.
- A flow is derived-from its capture and contains references to its observables.
- Reconstructed files, emails, attachments and email URL objects are
  derived-from their capture and the streams exposing the source content.

Observation times come from packet timestamps, independently of import time
or email Date headers. Capture/flow bounds use the minimum and maximum observed
time, even when packet records are not in timestamp order. MISP datetime fields
have microsecond precision; sub-microsecond fractions are truncated there and
preserved exactly in packet-record time_epoch strings. Missing timestamps do
not acquire the current time.

## Reconstructed content

HTTP exports are matched by SHA-256 to the decoded HTTP payload bytes exposed
by TShark. IMF/SMTP exports are matched to the exact reassembled message bytes
in a targeted second metadata pass. Filenames, subjects, Message-IDs and the
number of streams are not used to guess a source.

Identical exported content within one protocol becomes one content object
(or one email object group), retaining every stream on which the same bytes
were observed. HTTP exporter filename aliases are retained. Distinct payloads
using the same filename remain separate. Stream-reference comments record the
payload SHA-256 and completion_frames where TShark exposes the completed
payload.

Derived object attributes receive observation intervals from those completion
frames; these are not claimed to be the full transfer duration. The referenced
flow retains its broader packet interval. Email attachments and body URLs
inherit provenance through the matched carrier message, whose payload hash is
recorded in their stream-reference comments.

If no unambiguous payload-to-stream match is available, the object keeps its
capture reference and the response includes a warning. Corrupt emails still
fall back to file objects. Encrypted/incomplete traffic and other transfer
protocols retain the existing reconstruction limitations.

## Resource limits and requirements

TShark 4.0 or newer must be available on the service user's PATH. The module
isolates its Wireshark profile and disables name resolution.

Input is limited to 50 MiB. Exported files are limited to 100 MiB in aggregate,
and the two packet-metadata reports share a 100 MiB limit. Diagnostics and the
serialized MISP result each have a 100 MiB limit. Payload bytes represented
as hexadecimal also count toward packet metadata, so compressed content may
reach that limit before the export limit.

The timeout option defaults to 60 seconds and accepts positive finite values
up to 300. The SMTP pass receives only the remaining time after the initial
pass and context construction. Size checks continue every 50 ms during either
TShark process, with final checks after exit. Processes are killed/reaped and
temporary files removed on timeout or limit failure. These checks monitor
output sizes; they are not filesystem quotas and short bursts can overshoot.

Existing network observations and new capture/flow attributes have to_ids
disabled. Importing traffic does not establish that its indicators are malicious.
