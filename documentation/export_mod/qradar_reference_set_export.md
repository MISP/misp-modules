# QRadar Reference Set Export

`qradar_reference_set_export` produces a deduplicated list of one selected indicator
type for a QRadar reference set. It exports values from supplied MISP events and
objects, without contacting QRadar or requiring credentials. For direct workflow
publication, use [QRadar Reference Set Publish](../action_mod/qradar_reference_set_publish.md).
The two modules have distinct names because misp-modules registers module names
across all module families.

## Configuration and formats

Enable **QRadar Reference Set Export** in MISP's export-module settings. Set the
module configuration there, or supply `config` when calling `/query` directly:

| Configuration | Default | Meaning |
| --- | --- | --- |
| `indicator_type` | `ipv4` | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` or `sha512`. Export one type per run to keep reference sets separate. |
| `format` | `csv` | `csv` produces a headerless single-column UTF-8 file, one value per line, with standard CSV quoting. `json` produces a JSON array of strings. |
| `include_non_ids` | `false` | Include non-IDS attributes when explicitly enabled. Deleted data remains excluded. |

Boolean settings accept JSON booleans, integers 0/1 and strings `true`, `false`,
`1`, `0`. Empty settings use the documented defaults.

For CSV, create or select a compatible reference set in **Admin → Reference Set
Management**, view its contents, select **Import**, choose the file and the intended
QRadar domain, and import it. There is no header to remove. Do not add provenance
columns to the import file. Select the correct domain; shared reference data has
broader visibility than domain-specific data.

JSON is for tooling that consumes a value array. It is not a full request body for
the current `/reference_data_collections/set_entries` endpoint: that API expects
an object per entry, including collection and domain IDs. The companion action
constructs those objects. MISP's export extension/MIME metadata is static, so this
module advertises `.csv`/`text/csv` for both modes. Rename a JSON download to `.json`
when required; its contents are still JSON.

## Supported indicators and target types

| Selected type | MISP attributes | Normalization | Compatible QRadar entry type |
| --- | --- | --- | --- |
| `ipv4` | `ip-src`, `ip-dst`, IP component of `domain\|ip` | Validate and canonicalize IPv4. | `IP` |
| `ipv6` | Same IP attributes | Validate and canonicalize IPv6. Keep separate from IPv4 because QRadar's `IP` type stores IPv4. | `ALN` |
| `domain` | `domain`, `hostname`, domain component of `domain\|ip` | IDNA encode, lowercase, remove a trailing DNS dot, validate labels and the 253-character normalized name limit. | `ALN` or `ALNIC` |
| `url` | `url` | Require an absolute URL with a host, valid port and no whitespace; preserve case and the exact value. | `ALN` |
| `md5`, `sha1`, `sha256`, `sha512` | Corresponding hash types, `filename\|HASH`, and the MD5 component of `malware-sample` | Validate hexadecimal length and lowercase. Split filename composites at the last pipe. | `ALN` or `ALNIC` |

`ALN` is case-sensitive text; `ALNIC` ignores case. URLs use `ALN` to preserve
case-sensitive paths. IPv6 in a text set requires rules/properties that compare
compatible canonical text; it does not acquire the semantics of QRadar's IPv4
set type. Separate sets are recommended for each indicator type even when several
types share the same QRadar entry type.

Only supported values of the selected type are exported. Other types, malformed
values and unsupported attributes have separate skipped counts. CIDRs, scoped
IPv6, email addresses, filenames alone and port-qualified composites are excluded.
Port constraints are not discarded to create broader indicators. `domain|ip` is
validated as a whole before either component is selected. Control characters in
indicator values are rejected. No binary sample data is exported.

Standard (`{"Event": {...}}`), bare and legacy event envelopes are supported,
including lists of events. Only `to_ids=true` attributes are included by default.
Deleted events, objects and attributes are always excluded. Duplicate canonical
values are emitted once and sorted for deterministic files. Existing `file` and
`domain-ip` objects are supported; no additional object templates are needed.

## API example and response

POST to the misp-modules `/query` endpoint:

```json
{
  "module": "qradar_reference_set_export",
  "config": {"indicator_type": "domain", "format": "csv"},
  "data": [{
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "domain",
        "value": "EXAMPLE.org.",
        "to_ids": true
      }]
    }
  }]
}
```

The response has `response: []` and base64-encoded file contents in `data`. Here,
decoding `data` yields `example.org` followed by a newline. Empty selections produce
an empty CSV file or `[]` in JSON mode.

Additional API fields include `summary` with selected type, format, count and
skipped counts, and `sources`, mapping each exported value to its contributing
event/attribute/object references. Warnings describe skipped attributes. These
fields are not embedded in the import file. MISP's normal file download may not
display them; inspect the `/query` response when you need the audit details.
Malformed requests or configuration return `error` instead of a file.

Apply MISP sharing and handling policies before export.

The export has no network calls or action-specific 100-value limit. QRadar's own
value-length and import limits remain applicable. Tests validate serialization and
mocked service endpoints; no live QRadar import was performed.

References: [IBM IOC import instructions](https://www.ibm.com/docs/en/qradar-on-cloud?topic=overview-importing-iocs-reference-set)
and [QRadar reference-set types](https://www.ibm.com/docs/en/qradar-on-cloud?topic=overview-adding-editing-deleting-reference-sets).
