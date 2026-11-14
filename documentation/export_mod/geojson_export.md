# GeoJSON export

`geojson_export` exports MISP `geojson` and `geolocation` objects. It accepts bare
events, `{"Event": {...}}` wrappers, legacy wrappers with sibling `Object` arrays,
and lists of these events. Geographic context is included regardless of
`to_ids`. No configuration, extra dependencies or network calls are required.

Send a request to the misp-modules `/query` endpoint:

```json
{
  "module": "geojson_export",
  "data": {
    "Event": {
      "Object": [{
        "name": "geolocation",
        "comment": "Observation site",
        "Attribute": [
          {"object_relation": "latitude", "type": "float", "value": "49.61"},
          {"object_relation": "longitude", "type": "float", "value": "6.13"},
          {"object_relation": "altitude", "type": "float", "value": "290"},
          {"object_relation": "first-seen", "type": "datetime", "value": "2026-01-01T12:00:00Z"}
        ]
      }]
    }
  }
}
```

Decode the response's `data` to save a `.geojson` file:

```python
import base64
import json
from pathlib import Path

response = json.loads(Path("response.json").read_text(encoding="utf-8"))
if "error" in response:
    raise ValueError(response["error"])
Path("export.geojson").write_bytes(base64.b64decode(response["data"], validate=True))
```

The MIME type is `application/geo+json`. Module errors use `error`, including in
HTTP 200 responses. Warnings report place-only geolocation objects skipped
because they have no coordinates. Having only one coordinate is an error.

## Stored datasets

Include attachment data when fetching MISP events, for example using PyMISP's
`get_event(event_id, with_attachments=True)`. Every active `geojson.attachment`
must include its base64 bytes in `data`. Missing attachments or missing data
reject the export.

A single dataset is returned byte for byte when no additional points are
needed, preserving formatting, number spelling, UTF-8 BOM and all metadata.
The attachment is authoritative. Geolocations identified by active `contains`
references from an exported dataset are not added again. Editing or deleting a
derived location does not rewrite its stored dataset; export the geolocation
objects alone to export their current coordinates.

Multiple datasets, or datasets with standalone locations, produce one
FeatureCollection. Source features remain in dataset order, followed by the
standalone locations. Bare geometries are wrapped in Features with empty
properties. Feature properties, IDs (including duplicate IDs across datasets),
geometry collections, polygon holes and foreign members are retained. Decimal
numbers are serialized without conversion through binary floating point.

Collection-level metadata and original bounds move into a foreign member
named `misp:source-datasets`. Each entry records the source root `type`,
zero-based `feature-start` offset, `feature-count`, and, for FeatureCollections,
`metadata` containing all root members other than `type` and `features`.
Existing foreign members with that name remain nested in the source metadata.
The combined collection has no root `bbox`, since source bounds may be stale.
Formatting and numeric spelling may change when combining documents.

## Standalone geolocations

Each location becomes a Point Feature. Coordinates use **longitude, latitude,
optional altitude** in WGS84. Zero values are retained. An explicit `epsg` or
`spacial-reference` naming a different projection rejects the export. Coordinate
and altitude relations must each have a single value.

| MISP field | GeoJSON mapping |
| --- | --- |
| `longitude`, `latitude`, `altitude` | Point coordinates |
| Object UUID | Feature `id`, when present |
| Object comment, falling back to city or address | `properties.name` |
| `city`, `country`, `countrycode`, `region`, `address`, `zipcode`, `neighborhood` | Properties with the same names |
| `accuracy-radius` | Property with the same name, retaining MISP's kilometre units |
| `first-seen`, `last-seen` | Properties with the same names; no timestamp conversion |
| `text` values | `properties["misp:text"]` array |

Deleted events, objects, attributes and references are excluded. Imported
property JSON in a location's `text` remains analyst context in `misp:text`
when exported alone; it is not interpreted as instructions or merged into
properties. Unrelated event-level float attributes are not paired into points.

Total decoded source bytes and output are each limited to 20 MiB, with at most
10,000 features and 10,000 coordinate positions across the result. Input and
combined output also have the parser's 32-level nesting, 200,000-value and
256-character/exponent numeric limits. A bare geometry counts as one feature.
Validation matches the [importer](../import_mod/geojson_import.md), including
finite coordinates and rejection of legacy `crs` members. Any invalid dataset
or standalone coordinate rejects the entire export.
