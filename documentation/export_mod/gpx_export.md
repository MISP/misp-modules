# GPX export

`gpx_export` exports MISP `gpx` and `geolocation` objects. It has no configuration,
extra dependencies or network calls. It accepts bare events, standard
`{"Event": {...}}` wrappers, legacy wrappers with sibling `Object` arrays, and
lists of these events. Geographic context is included regardless of `to_ids`.

Send a request to misp-modules' `/query` endpoint:

```json
{
  "module": "gpx_export",
  "data": [{
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
  }]
}
```

The response's `data` is base64-encoded XML, suitable for saving as `.gpx`:

```python
import base64
import json
from pathlib import Path

response = json.loads(Path("response.json").read_text(encoding="utf-8"))
if "error" in response:
    raise ValueError(response["error"])
Path("export.gpx").write_bytes(base64.b64decode(response["data"], validate=True))
```

Module errors use `error`, including in HTTP 200 responses. Warnings describe
place-only geolocation objects omitted because they lack coordinates.

## Stored GPX datasets

Include attachment data when fetching MISP events, for example using PyMISP's
`get_event(event_id, with_attachments=True)`. Each active `gpx.attachment` must
contain its base64 XML in `data`. A missing attachment or missing data rejects
the export rather than silently losing tracks or routes.

A single attached GPX 1.0 or 1.1 document is returned byte for byte when no
additional waypoints are needed. This preserves all metadata, extensions,
encoding and formatting. The attachment is authoritative: geolocation objects
listed by its `contains` references are not added again. Edits to those derived
objects do not rewrite the stored track; export the geolocation objects alone
to export their current coordinates.

Multiple attachments, or an attachment with additional geolocations, produce
one GPX 1.1 document. Waypoints, routes, tracks and segment boundaries remain
distinct, in source order within each element type. The first document supplies
the primary metadata. Source root attributes, metadata and root extensions are
also retained under `extensions/misp:source`, using namespace
`https://www.misp-project.org/namespace/gpx/1`. Stale primary bounds are omitted.
Vendor extensions on geometry remain attached to their points/routes/tracks.
GPX 1.0 URLs become links; its metadata is converted to 1.1, and fields such as
track point speed/course move into extensions in the GPX 1.0 namespace.
Combining datasets changes XML formatting and namespace prefixes.
Extension values keep their source namespace bindings, including prefixes used
only in text or `xsi:type`, and prefixes reused differently by separate files.

## Geolocation mapping

| MISP field | GPX waypoint |
| --- | --- |
| `latitude`, `longitude` | Required `lat` and `lon` attributes |
| `altitude` | `ele`, in metres |
| `first-seen`, falling back to `last-seen` | `time`, normalized to UTC |
| Object comment, falling back to city or address | `name` |
| `text` values | `desc`, joined by newlines |

Coordinates are WGS84. An explicit `epsg` or `spacial-reference` specifying a
different projection rejects the export. Latitude must be in [-90, 90] and
longitude in [-180, 180), following the GPX schema. Decimal precision is retained;
scientific notation in MISP float values is expanded to decimal notation.
Timestamps without an offset are interpreted as UTC. Only one coordinate,
altitude and observation-time value per relation is supported. A time interval
uses its first observation; other location attributes have no GPX mapping.

Deleted events, objects, attributes and references are excluded. Source
attachments are opaque datasets: deleting a derived geolocation does not remove
its point from the stored file. Repeated coordinates remain distinct points.
The module does not pair unrelated event-level float attributes into locations.

Total decoded source data and output are each limited to 20 MiB, with at most
10,000 points and 32 source XML nesting levels. Generated decimal values are
limited to 256 digits/exponent magnitude. DTDs and entities are rejected. Invalid
coordinates, elevations, observation times or XML reject the entire export.
This is a GPX field parser, not full source XSD validation.
