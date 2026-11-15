# Suricata EVE observation import

`suricata_import` imports selected EVE JSON/JSONL findings and protocol observations.
It supplies inbound evidence mapping rather than an outbound IDS rule/intelligence
export. It does not execute Suricata, read a packet capture, fetch rules or contact
an endpoint. Single records, arrays and JSONL are accepted, with optional UTF-8 BOM.
Each record requires `timestamp` and `event_type`.

The importer retains EVE alert, flow, DNS, HTTP, TLS, fileinfo, anomaly and other
event types. Unknown event types remain raw source observations; they are not
automatically detections or protocol-specific entities. For example, a stats record
has source context but does not become a connection without valid endpoint/flow
information. Pass an already selected export or use the filters below.

Use `module: "suricata_import"`, base64 export bytes in `data`, optional `filename`,
and the following `config` settings:

| Setting | Meaning |
| --- | --- |
| `format` | `auto` (default), `json`, `jsonl`. Explicit formats are enforced. |
| `event_types` | Optional comma-separated event types or API list, such as `alert,flow,dns`. |
| `flow_ids` | Optional comma-separated/list unsigned 64-bit flow IDs. Combined with event-type filtering when both are set. |
| `sensor` | Fallback when native EVE `host` sensor context is absent; not an endpoint hostname. |
| `tool_version` | Optional producing Suricata version. |
| `capture_file` | Capture default when native `pcap_filename` is absent. Never opened. |
| `capture_sha256` | Optional producer-supplied capture SHA-256, never substituted with the log hash. |
| `capture_url` | Optional capture/investigation reference; never fetched. |

A collector can use the same `metadata` / `records` wrapper documented for
[Zeek import](zeek_import.md). Conflicting metadata/config values are errors.
Source `pcap_filename` takes precedence over the capture default. If it identifies
a different capture, the default hash/URL is not applied. When a row supplies a
native capture name, a default hash requires matching explicit `capture_file`
context. Missing capture hashes are not invented. `pcap_cnt` remains a packet
number in that capture, separate from the imported source record ordinal.

Each source record becomes a `network-observation`, with native flow ID,
transaction ID, packet number, Community ID, sensor/interface and raw protocol
fields. Alerts preserve SID, GID, revision, signature message, category, severity
and reported action. IDs/ports are validated as bounded unsigned integers before
promotion; invalid values remain raw. Flow IDs retain full 64-bit precision and
are never parsed as floats. Version-1 Community IDs are retained only when valid;
unsupported IDs remain raw and no ID is computed with a guessed seed.

Existing `network-connection` objects represent validated source/destination
endpoints and transport as reported. A `to_client` event can reverse the source/
destination tuple relative to other records on that flow; the importer does not
relabel endpoints as client/server or guess directional byte counters. Nested
`flow.start/end` provide connection bounds when explicit and consistent. A packet/
alert log timestamp is not silently relabeled as the first packet of a connection.
An inverted interval remains raw without normalized observation/connection bounds.

EVE ISO dates support native offsets such as `+0000` as well as colon offsets.
Offsets must be known, and at most microsecond precision is normalized. Local
times, `-0000` / `-00:00`, unsupported precision and numeric times without native
ISO semantics stay raw with warnings; import time is never substituted. The full
raw record preserves protocol substructures, rule metadata, payload references,
file hashes, DNS answers and unknown fields without executing them.

Flow IDs, Community IDs and matching tuples never merge records across runs,
sensors or captures. A reported `allowed`/`blocked` action or alert category does
not establish an analyst-confirmed malicious verdict or prove remediation. Results
start as `unreviewed`; all attributes are non-IDS and non-correlating. Existing
Suricata rule templates are not used to fabricate rule bodies from SID/message data.

The source file retains the exact original attachment only when all records are
included. Filtering omits that full attachment to prevent disclosure of excluded
records; only selected raw records remain, with original record ordinals and the
hash/size/name of the externally retained input. A filter matching no records is
an error. `pcap-metadata` retains supplied capture references, separately from log
export hashes, with source-to-derived provenance links. No PCAP bytes are loaded.

Limits: 20 MiB input, 1000 records before filtering, 128 KiB per normalized record,
32 nesting levels. Invalid structure, duplicate JSON keys and invalid explicit
configuration return atomic errors; recoverable field/time problems retain raw
context with warnings. The bundled `network-observation` definition supports older
PyMISP template inventories. See [native fixture provenance](../../tests/fixtures/network_observation/README.md).
