# KML and KMZ export

`kml_export` and `kmz_export` export MISP `kml` dataset objects and standalone
`geolocation` objects. No configuration, additional dependencies or network
calls are required. Include attachment data when fetching events, for example
using PyMISP's `get_event(event_id, with_attachments=True)`.

| Exporter | Behavior |
| --- | --- |
| `kml_export` | Export standalone locations as KML, or return one stored KML unchanged when no additional points are needed |
| `kmz_export` | Export locations, wrap KML in KMZ, return one stored KMZ unchanged, or combine datasets and additional locations while retaining package assets |

Use `kmz_export` for a KMZ input, several source datasets, or a source dataset
plus additional points. `kml_export` rejects those cases with an actionable
error, since a single XML file cannot carry KMZ assets or preserve separate
source-document style scopes without rewriting them.

Send a request to misp-modules' `/query` endpoint:

```json
{
  "module": "kmz_export",
  "data": {
    "Event": {
      "Object": [{
        "name": "geolocation",
        "comment": "Observation site",
        "Attribute": [
          {"object_relation": "latitude", "type": "float", "value": "49.61"},
          {"object_relation": "longitude", "type": "float", "value": "6.13"},
          {"object_relation": "first-seen", "type": "datetime", "value": "2026-01-01T12:00:00Z"}
        ]
      }]
    }
  }
}
```

Decode response `data` to save the output:

```python
import base64
import json
from pathlib import Path

response = json.loads(Path("response.json").read_text(encoding="utf-8"))
if "error" in response:
    raise ValueError(response["error"])
Path("export.kmz").write_bytes(base64.b64decode(response["data"], validate=True))
```

Use `kml_export` and save `.kml` for XML output. MIME types are
`application/vnd.google-earth.kml+xml` and `application/vnd.google-earth.kmz`.
Module errors use `error`, including in HTTP 200 responses; warnings report
place-only locations skipped because they lack coordinates.

## Source datasets and assets

Every active dataset must have an active attachment with base64 bytes in
`data`. Missing attachments/data or an invalid source reject the export. Bare
events, `{"Event": {...}}` wrappers, legacy wrappers with sibling `Object`
arrays, and lists of events are accepted. Geographic context is included
regardless of `to_ids`.

The source attachment is authoritative. Geolocations identified by its active
`contains` references are not added again. Editing or deleting derived
locations does not rewrite their stored source geometry; export those locations
alone to export their current values. Deleted events, objects, attachment
attributes and references are excluded.

A single KML returned by `kml_export`, or a single KMZ returned by `kmz_export`,
is byte-for-byte unchanged when no additional points are needed. One KML
wrapped in KMZ retains its XML bytes and a safe `.kml` basename.

For combinations, the KMZ begins with a `doc.kml` index containing local
NetworkLinks to separate `datasets/0001/`, `datasets/0002/`, ... directories.
Every source package's files keep their relative paths and bytes. Styles,
identifiers, references, folder hierarchies, overlays and vendor namespace
bindings remain in their original XML documents, preventing collisions between
identically named icons or styles in different datasets. Standalone locations
are Placemarks in the index. Re-import follows those local links and recovers
the extracted observations. ZIP metadata/compression and directory entries may
change when combining; original source file contents do not.

## Standalone locations

Longitude and latitude are required together, with a single finite value per
relation. Zero values and decimal precision are retained. A location with
neither coordinate is skipped with a warning; one missing coordinate is an
error. Explicit `epsg`/`spacial-reference` fields must specify WGS84 EPSG:4326.

| MISP field | KML representation |
| --- | --- |
| Longitude, latitude | Point coordinates in that order |
| Object comment, falling back to city/address | Placemark name |
| Equal first/last seen | TimeStamp |
| Distinct or open first/last seen | TimeSpan begin/end |
| Text notes | Plain-text-safe description and `misp:text` ExtendedData containing the JSON array |
| Object UUID | `misp:uuid` ExtendedData |
| City, country, countrycode, region, address, zipcode, neighborhood, accuracy-radius | `misp:<relation>` ExtendedData |
| WGS84 altitude | `misp:altitude-wgs84` ExtendedData, preserving its numeric value without assuming a sea-level conversion |

Generated Points use two-dimensional coordinates and default terrain clamping.
No geoid model is applied to WGS84 altitude. Accuracy radius retains MISP's
kilometre units in ExtendedData. Times require complete timezone-qualified
instants at microsecond precision or less and are normalized to UTC; an
inverted interval is rejected. Other metadata remains contextual rather than
being interpreted as HTML, geometry, style definitions or instructions. Re-import
retains ExtendedData in observation context; it does not promote arbitrary
ExtendedData into typed MISP attributes.

Total original source bytes and expanded source data are each limited to
20 MiB. Output is also limited to 20 MiB, with at most 1,000 datasets/members,
10,000 coordinates, 10,000 Placemarks and 200,000 parsed XML elements. The
[importer's](../import_mod/kml_import.md) XML, numeric, archive and geometry
limits also apply. Generated packages are parsed before returning them, so
they obey the same limits on re-import. Errors return no partial data.
