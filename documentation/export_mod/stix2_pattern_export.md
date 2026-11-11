# STIX2 Pattern Export

Exports STIX 2.1 patterns from one or more MISP events, including attributes inside objects. Install `misp-modules[all]` for the existing `misp-stix>=2026.10.12` dependency. No configuration or network service is required.

Post an export request to `/query`:

```json
{
  "module": "stix2_pattern_export",
  "data": [
    {
      "Event": {
        "info": "Example event",
        "Attribute": [
          {"type": "domain", "value": "example.org", "to_ids": true},
          {"type": "ip-dst|port", "value": "192.0.2.1|443", "to_ids": true}
        ]
      }
    }
  ]
}
```

The response's `data` is base64-encoded UTF-8 JSON, with extension `.json` and MIME type `application/json`. Decode it to obtain an array of standalone pattern strings:

```json
[
  "[domain-name:value = 'example.org']",
  "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '192.0.2.1' AND network-traffic:dst_port = '443']"
]
```

Consumers must parse the JSON array and evaluate each pattern independently. The array preserves complete stored patterns, including multiline formatting, logical operators, observation operators and qualifiers. Event metadata, labels and STIX Indicator validity times are not included; use the full STIX export when a STIX Bundle is needed.

The module accepts a bare event, an `Event` envelope, a list of either, and the legacy export format with `Attribute` and `Object` beside `Event`. Object attributes are treated individually, as in the YARA export; object relations are not combined into an object-wide pattern. A composite attribute such as `filename|sha256` or `ip-dst|port` remains one conjunctive pattern.

Stored `stix2-pattern` attributes are exported even when `to_ids` is false, following the YARA export convention for stored rules. Other types must have `to_ids` set to true (`true`, `1`, `"true"`, or `"1"`). Deleted events, objects and attributes are excluded. Duplicate pattern strings are removed, and the output is sorted for repeatable exports.

Every complete pattern is checked with the STIX 2.1 syntax validator. Unsupported attributes, conversion warnings/errors and invalid patterns are skipped and counted under `summary.skipped["invalid or unsupported conversion"]`, with a response warning. If no patterns can be exported, the module returns an error and counts, without an empty download.

## Existing misp-stix mappings

Generation calls the public `MISPtoSTIX21Parser.parse_misp_attribute()` API and extracts only STIX Indicators with `pattern_type="stix"`. This reuses upstream mappings, literal escaping, hash algorithm names, address direction and composite conjunctions. Conversion errors and warnings are treated as unsuccessful conversion, so a warning about an incomplete composite cannot silently broaden a rule.

Upstream already provides [MISP attribute-to-STIX mappings](https://github.com/MISP/misp-stix/blob/main/misp_stix_converter/misp2stix/stix2_mapping.py), [MISP-to-STIX conversion](https://github.com/MISP/misp-stix/blob/main/misp_stix_converter/misp2stix/misp_to_stix2.py), and [STIX pattern-to-MISP mappings](https://github.com/MISP/misp-stix/blob/main/misp_stix_converter/stix2misp/converters/stix2_indicator_converter.py). Stored `stix2-pattern` attributes are validated directly, because a standalone attribute of this type is not currently mapped to a STIX Indicator by the attribute converter.

Validation checks STIX 2.1 syntax. Observable field selection and value representation follow the installed misp-stix version. For a full STIX Bundle with event and object context, use MISP's STIX export or misp-stix directly.
