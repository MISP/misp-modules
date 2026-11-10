# STIX2 Pattern Generator

Generates a `stix2-pattern` attribute from a supported MISP attribute, with expansion and hover support. Install `misp-modules[all]` for the existing `misp-stix>=2026.10.12` dependency. No configuration or network service is required.

For example, post this request to `/query`:

```json
{
  "module": "stix2_pattern",
  "attribute": {
    "type": "filename|sha256",
    "value": "example.exe|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

The response uses MISP standard format (`results.Attribute`) and contains one attribute of type `stix2-pattern`, whose value is:

```text
[file:name = 'example.exe' AND file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']
```

Legacy requests such as `{"module":"stix2_pattern","domain":"example.org"}` also work. `/modules` lists the complete supported input types: file hashes and filename/hash composites, domain and hostname, IPv4/IPv6 source and destination addresses and address/port composites, URLs, email attributes, registry keys, mutexes, AS numbers, and other mapped indicators.

Generation explicitly sets `to_ids=True` for conversion, so a non-IDS source attribute can also be used. The generated rule has `to_ids=True`; the source attribute is not modified. Deleted attributes are rejected. Invalid inputs, conversion errors or warnings, missing patterns, and invalid STIX syntax return an `error` without a partial result.

## Existing misp-stix mappings

The module calls the public `MISPtoSTIX21Parser.parse_misp_attribute()` API and extracts the STIX Indicator's `pattern`. It validates the entire result with `stix2patterns.validator.run_validator(..., stix_version="2.1")`. It does not reproduce the converter's mapping or interpolate values into STIX expressions. This preserves upstream literal escaping, hash algorithm names, source/destination direction and composite conjunctions.

The upstream [MISP-to-STIX mapping](https://github.com/MISP/misp-stix/blob/main/misp_stix_converter/misp2stix/stix2_mapping.py) already maps these MISP attribute types. The [STIX indicator converter](https://github.com/MISP/misp-stix/blob/main/misp_stix_converter/stix2misp/converters/stix2_indicator_converter.py) also maps STIX patterns back into MISP attributes and objects. This module implements the MISP-to-pattern generator, analogous to `yara_query`; reverse conversion remains available through misp-stix's STIX import APIs.

Validation checks STIX 2.1 syntax. Observable field selection and value representation follow the installed misp-stix version. The output is a pattern expression; it does not include STIX Indicator metadata, event context or a STIX Bundle.
