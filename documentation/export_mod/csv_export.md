# Generic CSV export

`csv_export` exports attributes of any MISP type without a vendor-specific
schema. It requires no configuration or additional Python packages.

The website bundles the same standard-library exporter in its own package, so
CSV downloads also work with the older `misp-modules` versions in its lockfile.
A synchronization test keeps the bundled copy identical to the API module.

In the MISP Modules website, open an enrichment result and select **Download
CSV** underneath the module name. The action is available in every result tab
for both active and saved queries. **Download JSON** remains available beside
it. Both standard `Attribute`/`Object` responses and legacy `types`/`values`
responses are supported. For legacy results, each value produces a row for each
suggested type. The `event_info` column identifies the module and original query.
Module errors and responses without an attribute result return an error instead
of a CSV file. Empty attribute results download a header-only CSV.

## Module API

POST this request to the module server's `/query` endpoint:

```json
{
  "module": "csv_export",
  "data": [
    {
      "Event": {
        "uuid": "6b5df9d7-dd40-49f8-8a7c-de4776efaf0b",
        "info": "Example investigation",
        "Attribute": [
          {"type": "domain", "value": "example.org", "to_ids": false}
        ]
      }
    }
  ]
}
```

The response contains `response: []` and a `data` field holding base64-encoded
UTF-8 CSV. The module advertises `text/csv` and the `.csv` extension for event
and event-collection exports. Bare events and legacy export envelopes (collections
beside `Event`) are also accepted.

Every supplied event is processed, including standalone attributes, object
attributes and attributes with `to_ids` disabled. Deleted events, objects and
attributes are excluded. Composite values are preserved in one cell; rows are
not deduplicated, so distinct source attributes remain distinct.

The fixed columns are:

* Event context: `event_id`, `event_uuid`, `event_info`.
* Object context: `object_uuid`, `object_name`, `object_relation`.
* Attribute fields: `uuid`, `category`, `type`, `value`, `comment`, `to_ids`,
  `distribution`, `timestamp`, `first_seen`, `last_seen`.
* Tags: `event_tags`, `object_tags`, `attribute_tags`, each containing a JSON
  array of sorted tag names.

Missing scalar fields are empty. CSV uses commas, a header, CRLF record endings
and standard quoting for commas, quotes and embedded newlines. Unicode is
preserved. Formula-like cells starting with `=`, `+`, `-` or `@` (including after
leading ASCII whitespace/control characters), and cells starting with a tab,
carriage return or newline, receive an apostrophe prefix. This intentionally
changes those cells for spreadsheet safety; use the JSON download when exact
original values are needed.

This is an attribute report, not a complete event backup. Binary attachment
contents, object references, galaxies and other event structures are not included.
