# GeoJSON import

`geojson_import` accepts UTF-8 GeoJSON geometries, Features and FeatureCollections
using WGS84 coordinates as defined by RFC 7946. Upload a file or paste JSON in
MISP's import interface. For `/query`, base64-encode the original bytes:

```python
import base64
import json
from pathlib import Path

request = {
    "module": "geojson_import",
    "filename": "observations.geojson",
    "data": base64.b64encode(Path("observations.geojson").read_bytes()).decode("ascii"),
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

The response contains `results.Object`; errors use `error`, including in HTTP
200 responses. The module does not save results to a MISP event. It uses the
existing `geojson` v1 and `geolocation` v8 templates bundled with the project's
minimum PyMISP version. No template changes, extra dependencies or network
lookups are needed.

| GeoJSON source | MISP representation |
| --- | --- |
| Original bytes | `geojson.attachment`, filename, MIME type, size, MD5, SHA1 and SHA256 |
| Features | `feature-count`; standalone geometries and Features count as one feature |
| Geometry types | Repeated `geometry-types` attributes, including nested GeometryCollections |
| All geometry positions | Minimum/maximum longitude and latitude, derived from coordinates |
| Root `name` and `description` string foreign members | `name` and `description-text` |
| Each Point or MultiPoint position, including in GeometryCollections | A linked `geolocation` with longitude, latitude, EPSG 4326 and WGS84 reference |
| Third coordinate | `geolocation.altitude`, in metres |
| Feature `id` and `properties` | JSON in `geolocation.text`; also retained in the original attachment |
| Point position in dataset | Object comment and a `contains` reference from the dataset |

Coordinate order is **longitude, latitude, optional altitude**. All attributes
have `to_ids=false`. Numeric decimal precision is preserved. Repeated points
remain separate observations. There is no standard GeoJSON timestamp property,
so properties such as `time` or `timestamp` are retained without inferring
`first-seen` or `last-seen` values.

LineString, MultiLineString, Polygon and MultiPolygon geometries remain intact
in the attachment; their vertices do not become standalone observations.
Feature properties, identifiers, foreign members, null geometries, polygon
holes and collection structure are retained there. Empty coordinate arrays
are treated as empty geometries. Empty datasets still produce a dataset object.

Bounds are coordinate extrema, not a minimum antimeridian-crossing envelope.
Declared `bbox` values stay in the attachment and do not override observed
coordinates. `filename` defaults to `import.geojson`; directory components are
removed, and no supplied path is opened. A UTF-8 BOM is accepted and preserved.

Input is limited to 20 MiB, 10,000 features, 10,000 coordinate positions,
32 JSON nesting levels and 200,000 JSON values/containers. Expanded point
properties are also limited to 20 MiB in total, to bound repeated MultiPoint
properties. Numbers are limited to 256 characters and exponent magnitude 256.
Latitude must be in [-90, 90] and longitude in [-180, 180]. Positions must have
two or three finite numeric coordinates. Nonempty lines require at least two
positions; nonempty polygon rings require at least four and must be closed.

Invalid JSON, duplicate member names, non-finite numbers, malformed geometry
structures, out-of-range coordinates and legacy `crs` members reject the entire
import. Reproject legacy datasets to WGS84 and remove `crs` before importing.
This is structural and coordinate validation, not polygon topology validation;
ring winding, self-intersections and hole containment are not checked.
