# KML/KMZ import

`kml_import` accepts KML XML or a KMZ archive, detecting the format from the
contents. It preserves the original file in a `kml` dataset object and creates
linked `geolocation` observations for Point geometries and nonempty `gx:Track`
samples. All attributes have `to_ids=false`. No external service, additional
runtime dependency or resource download is required.

The new [`kml` v1 template](https://github.com/MISP/misp-objects/pull/583) is
bundled with the module for older PyMISP releases.
Install it in MISP's object catalog for the corresponding editor/display
support. One template describes both formats through `source-format` and MIME
type; KMZ assets remain inside the original attachment.

Upload a file or paste KML XML in MISP's import interface. For `/query`,
base64-encode the original bytes:

```python
import base64
import json
from pathlib import Path

request = {
    "module": "kml_import",
    "filename": "observations.kmz",
    "data": base64.b64encode(Path("observations.kmz").read_bytes()).decode("ascii"),
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

The response contains `results.Object`; errors use `error`, including in HTTP
200 responses. The module does not save results to a MISP event. Filenames
have directory components removed and default to `import.kml` or `import.kmz`.
No supplied filesystem path is opened.

| Source | MISP representation |
| --- | --- |
| Original XML or complete archive | `kml.attachment`, filename, source format, MIME type, size and hashes |
| Entry document's root feature name/description | Dataset `name` and `description-text` |
| KMZ package | `entry-document` and file `archive-member-count` |
| Parsed Placemarks and geometry | Placemark count, coordinate count, observation count and geometry types |
| Parsed coordinate positions | Minimum/maximum WGS84 longitude and latitude |
| Point and nonempty `gx:Track` positions | Linked geolocations with longitude, latitude, EPSG 4326 and WGS84 reference |
| Complete timezone-qualified observation times | `first-seen`/`last-seen`; dataset `start-time`/`end-time` |
| Source feature and altitude context | JSON in each geolocation's `text` attribute |

## Geometry and source context

The parser follows the KML feature hierarchy through Document and Folder
containers. It recognizes Point, LineString, LinearRing, Polygon with holes,
MultiGeometry, `gx:Track` and `gx:MultiTrack`. Coordinates use **longitude,
latitude, optional altitude**. Decimal values are preserved without converting
through binary floating point. Lines and polygon vertices contribute to bounds
and coordinate counts without becoming independent observations. Repeated
points and track samples remain distinct observations.

Track `<when>` and `<gx:coord>` arrays must have equal lengths; optional angles
must have that length too. Empty coordinate samples are retained in the source
and omitted from extracted observations. Track times belong to their samples;
Placemark TimeStamp/TimeSpan values apply to Point observations in that feature.

Context records the source document path, Placemark number and ID, folder
names, feature name/description, ExtendedData XML, geometry type, altitude mode
and source height, plus track sample index/time where applicable. Point names
become object comments. Styles, StyleMaps, overlays, Model anchors, tours,
views, arbitrary extensions and other payloads remain in the attachment.
Coordinates inside those payloads are not treated as Point observations.
Visibility, view-dependent loading and polygon topology are not evaluated.

KML uses sea-level, ground-relative and sea-floor altitude modes. These values
are **not** assigned to `geolocation.altitude`, whose WGS84 height cannot be
obtained without an appropriate vertical-datum conversion. Both source height
and mode remain in context, including default `clampToGround`.

Bounds are coordinate extrema rather than a minimum antimeridian-crossing
envelope. Geometry has coordinate/ring structure validation, not full KML XSD
or polygon topology validation. KML 2.2 namespace (also used by 2.3), legacy
Google KML 2.0/2.1/2.2 namespaces and unnamespaced documents are accepted.

## Times

Complete timezone-qualified timestamps with at most six fractional digits are
normalized to UTC. A TimeStamp supplies equal first/last times; a TimeSpan can
have an open begin or end. A fully dated begin later than its end is rejected.
XML end-of-day `24:00:00` is normalized to the following day.

Year-only, year/month, date-only, timezone-less times and fractions longer than
six digits stay in context without inventing missing precision or a timezone.
The parser accepts positive years 0001–9999 and fractions up to 64 digits;
leap-second values are unsupported. Container time primitives are not inferred
as observation timestamps.

## KMZ and resource resolution

The entry document is root-level `doc.kml` when present; otherwise the package
must have one unambiguous root-level `.kml` file. Local NetworkLinks to `.kml`
members are followed once per document, with cycle detection, relative URL
resolution and `xml:base` handling. An archive member with no incoming link is
retained without being parsed as an additional layer. Each parsed document's
geometry contributes to the dataset counts and bounds.

Remote links, filesystem URLs, paths escaping the package, missing members,
nested KMZ targets and query/fragment-dependent links are preserved without
resolution and produce a response warning. External icons, schemas, overlays
and other assets are never fetched. No KMZ member is extracted to disk.

Input files and total expanded archive data are limited to 20 MiB, with at most
1,000 ZIP members, 10,000 parsed Placemarks, 10,000 coordinate positions,
32 XML nesting levels and 200,000 parsed XML elements across linked documents.
Expanded observation context is limited to 20 MiB. Numeric values support at
most 256 characters and exponent magnitude 256. Latitude must be in [-90, 90]
and longitude in [-180, 180].

DTDs/entities, unsafe member paths, duplicate/case-ambiguous names, symlinks,
encryption, compression other than stored/deflated ZIP, malformed XML,
unsupported roots and invalid supported geometry/time fields reject the whole
import. Empty KML datasets are accepted. Source bytes, including XML formatting,
encoding, asset contents and ZIP metadata, stay in the attachment unchanged.
