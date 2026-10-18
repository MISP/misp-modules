# Splunk lookup export

`splunk_export` creates a UTF-8 CSV lookup from one or more MISP events. It includes
both event attributes and attributes inside objects. It needs no Splunk credentials,
network access or extra Python packages. Existing MISP objects such as `domain-ip`,
`file`, `email` and `network-connection` can supply the attributes; no new templates
are required.

## Configure and export

Enable **Splunk Lookup Export** in MISP's export module settings. By default only
attributes with `to_ids=true` are exported. The optional module configuration
`include_non_ids=true` also includes contextual attributes. Boolean values and
strings `true`, `false`, `1` and `0` are accepted. Deleted attributes, objects and
events are always excluded.

The API accepts `data` as a list of standard MISP events (`{"Event": {...}}), bare
event dictionaries, or legacy export envelopes with `Attribute` and `Object`
alongside `Event` metadata. For example, POST this JSON to `/query`:

```json
{
  "module": "splunk_export",
  "config": {"include_non_ids": false},
  "data": [{
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "info": "Example indicators",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "ip-dst",
        "value": "192.0.2.1",
        "to_ids": true
      }]
    }
  }]
}
```

Decode the response's base64 `data` field and save it as `misp_indicators.csv`.
Unsupported attribute types and malformed values are skipped; the API response's
optional `warnings` list reports their counts. The MISP download UI may not display
these warnings. An export with no eligible indicators produces the CSV header only.

## Supported indicators

| MISP type | Lookup `indicator_type` | Suggested CIM field(s) |
| --- | --- | --- |
| `ip-src`, `ip-dst` | `ip` | `src_ip`, `dest_ip` respectively |
| `domain` | `domain` | DNS `query` |
| `hostname` | `hostname` | `dest` |
| `url` | `url` | `url` |
| `email-src`, `email-dst` | `email` | `src_user`, `recipient` respectively |
| `filename` | `filename` | `file_name` |
| `md5`, `sha1`, `sha256`, `sha512` | Corresponding hash type | `file_hash` |
| `domain\|ip` | Separate `domain` and `ip` rows | `query`; `src_ip,dest_ip` |
| `ip-src\|port`, `ip-dst\|port`, `hostname\|port` | `ip` or `hostname` | As above, with a separate `port` column |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `filename\|sha512`, `malware-sample` | Separate `filename` and hash rows | `file_name`, `file_hash` |

`cim_fields` contains mapping hints, not a complete CIM event schema or a Splunk
Enterprise Security threat-intelligence import schema. Choose the field appropriate
to your data model and sourcetype. A composite attribute produces independent
hunting pivots, not a detection requiring all components to match. Its
`original_value`, `attribute_uuid` and optional `port` preserve that association.

Values are preserved exactly, including IPv6 addresses, letter case and Unicode;
this module is not a type validator. Lookup matching is exact by default, not CIDR,
wildcard, URL-host or subdomain matching. Normalize both lookup values and telemetry
where needed. A domain lookup against `query` does not match every URL containing
that domain.

## Columns and provenance

The stable header is:

```text
indicator,indicator_type,cim_fields,port,misp_type,original_value,event_uuid,event_id,event_info,attribute_uuid,object_uuid,object_name,object_relation,category,comment,to_ids,tags,first_seen,last_seen
```

`tags` is a sorted JSON array combining supplied event, object and attribute tags,
including TLP and confidence tags when present. No confidence is inferred.
`first_seen` and `last_seen` are observations copied from the attribute, not expiry
times. Rows are deduplicated only when all columns agree; separate source events,
attributes and object contexts remain distinguishable. CSV quoting preserves
commas, quotes and newlines without changing the underlying indicator values.

The lookup contains the data supplied to the module. Apply your intended sharing
policy when selecting events and distributing the resulting file. Tags remain
metadata; Splunk does not automatically enforce their handling rules.

## Upload and hunt

Upload the CSV under **Settings > Lookups > Lookup table files**, and grant the
intended Splunk app and roles access. These examples use the lookup filename
directly. For indicators shared by multiple MISP sources, create a lookup definition
with sufficient `max_matches` to return all sources; a file lookup's default match
limit may return only the first source. Use the definition name in searches instead
of the filename when using custom settings.

This bounded network search assumes CIM-normalized `dest_ip` values in an index
named `network`. Adapt the index and field names to your deployment:

```spl
index=network earliest=-24h latest=now
| eval misp_match_type="ip"
| lookup misp_indicators.csv indicator_type AS misp_match_type indicator AS dest_ip
    OUTPUT event_uuid AS misp_event_uuid attribute_uuid AS misp_attribute_uuid
| where isnotnull(misp_attribute_uuid)
| table _time src_ip dest_ip misp_event_uuid misp_attribute_uuid
```

For MD5 file telemetry, use the corresponding algorithm as the lookup key. This
avoids matching a file name or a different indicator type with the same text:

```spl
index=endpoint earliest=-24h latest=now
| eval misp_match_type="md5"
| lookup misp_indicators.csv indicator_type AS misp_match_type indicator AS file_hash
    OUTPUT event_uuid AS misp_event_uuid attribute_uuid AS misp_attribute_uuid
| where isnotnull(misp_attribute_uuid)
| table _time dest file_name file_hash misp_event_uuid misp_attribute_uuid
```

These searches perform indicator matching only. The network example does not
enforce the optional port constraint or MISP direction; add those conditions if your
detection requires them. Refresh or replace the lookup as indicators change: this
module does not synchronize deletions or expire indicators in Splunk.
