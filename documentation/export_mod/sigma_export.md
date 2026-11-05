# Sigma Rule Export

`sigma_export` exports a MISP event or collection as a ZIP containing Sigma YAML
files under `rules/` and a `manifest.json` recording source event, object and
attribute identifiers. It operates locally and does not contact a SIEM or deploy
rules. PyYAML is a direct project dependency.

MISP's existing `sigma_queries` and `sigma_syntax_validator` modules are
expansion/hover tools. They convert or validate an existing Sigma attribute;
this export module implements the event-download capability requested in
[issue #192](https://github.com/MISP/misp-modules/issues/192).

## Modes

| `config.mode` | Behavior |
| --- | --- |
| `rules` (default) | Copy existing `sigma` attributes, including attributes inside Sigma objects, without changing their contents. |
| `indicators` | Generate experimental Windows Sigma rules from supported indicators; omit stored rules. |
| `both` | Include stored rules and generated indicator rules. |

Stored Sigma attributes are exported regardless of `to_ids`, as detection rules
are often stored with that flag disabled. They are copied as received, without
parsing or validation; rule IDs, multi-document collections, correlation
references and formatting are retained. Invalid contents or conflicting IDs in
different stored files remain the analyst's responsibility. A Sigma object that
contains only a rule name and no `sigma` attribute has no rule contents to export.

Generated rules use only `to_ids` attributes unless
`config.include_non_ids=true`. Boolean options also accept `0`, `1`, `"0"`,
`"1"`, `"true"` and `"false"`. Deleted events, objects and attributes are excluded
in every mode. Input supports standard `{"Event": {...}}`, bare events and the
legacy split event/attribute/object export envelope.

## Generated rules and telemetry

IOC generation is opt-in. All generated rules use `product: windows` and the
following [Sigma log-source taxonomy](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-appendix-taxonomy.md).
They target fields normally provided by Windows Sysmon or an equivalent
normalised telemetry pipeline, rather than arbitrary raw event channels.

| MISP type | Sigma category and selection |
| --- | --- |
| `md5`, `sha1`, `sha256`, `imphash` | `process_creation`: `Hashes\|contains` with the algorithm prefix and validated hash |
| `filename` | `process_creation`: exact `Image` for Windows absolute paths, or `Image\|endswith` with a path boundary for filenames/relative paths |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `filename\|imphash`, `malware-sample` | `process_creation`: filename **and** hash in the same selection |
| `domain` | `dns_query`: `QueryName` matches the domain or its subdomains, with optional trailing dot |
| `hostname` | `dns_query`: exact `QueryName`, with optional trailing dot |
| `ip-src`, `ip-dst` | `network_connection`: `SourceIp` or `DestinationIp`; CIDRs use the `cidr` modifier |
| `ip-src\|port`, `ip-dst\|port` | `network_connection`: address **and** corresponding port in the same selection |

Hash case, IP representations, port numbers and DNS names are normalised.
Internationalised DNS names use IDNA. Filename wildcard characters are treated
literally, independently of YAML quoting. Ports must be 1–65535; scoped IPv6
addresses and POSIX filenames are unsupported. Other types, including
`domain|ip`, are reported as skipped rather than split into weaker conditions
or combined across incompatible log sources.

Generated files are marked `status: experimental` and `level: medium`. Review
the supplied intelligence and false positives, enable the relevant telemetry
(including process hashing, DNS queries and network connections), and convert
with a Sigma backend and processing pipeline appropriate to the destination
SIEM. The export is not a backend-specific SIEM query or a complete deployment
configuration.

## Use in MISP or through the module API

Restart misp-modules after installation, enable **Sigma Rule Export** in MISP's
export settings and select it when exporting an event. The API identifier is
`sigma_export`; `/modules` advertises a ZIP output and its configuration options.
Set `mode` to `indicators` or `both` when the event contains IOCs rather than
stored Sigma rules.

An API request has this form:

```json
{
  "module": "sigma_export",
  "data": [{
    "Event": {
      "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
      "info": "Example detection export",
      "Attribute": [{
        "uuid": "cb8bf166-ed67-433d-a211-4d3c475b5c07",
        "type": "ip-dst|port",
        "value": "192.0.2.1|443",
        "to_ids": true
      }]
    }
  }],
  "config": {"mode": "indicators"}
}
```

Send the JSON to `/query` and base64-decode the response's `data` field to a ZIP
file. Inspect `error` before saving: module errors use the usual JSON response
and may have HTTP status 200.

Each generated detection gets a deterministic UUIDv5 derived from its log source
and selection. Stored filenames derive from their exact content hash. Duplicate
files are combined while the manifest retains all source references. Sorting
and fixed ZIP metadata make exports deterministic for equivalent inputs.
`summary.stored_rules` and `summary.generated_rules` count unique rule files;
one stored file can itself contain a multi-document collection. Skipped counts
appear in the response and manifest; response warnings describe them. If no rules are
selected, an error is returned rather than an empty download.

Exports are limited to 1,000 unique rule files, 1 MiB per rule file and 20 MiB of
rule contents. Limit violations return an error rather than a partial archive.

## Validation

`tests/test_sigma_export.py` checks generated rules against SigmaHQ's
[detection-rule JSON schema](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/json-schema/sigma-detection-rule-schema.json),
copied to `tests/test_files/sigma_detection_rule_schema.json` (upstream blob
`018af59a36bacc4b986676ec888fb2cb1a971736`). It also exercises real PyMISP
serialization, event envelopes, flag handling, limits, determinism, provenance
and HTTP discovery/downloads.

The generated examples were additionally parsed and converted by pySigma 2.0.2
in an isolated environment. That avoids replacing the legacy `sigma` package
used by the existing expansion modules. No live SIEM was used; successful
conversion still requires a backend and pipeline for the deployment's fields.
