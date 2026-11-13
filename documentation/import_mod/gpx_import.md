# GPX import

`gpx_import` accepts GPX 1.0 and 1.1 XML, with the official GPX namespace or
without a namespace. Upload a file or paste XML through MISP's import interface.
For `/query`, base64-encode the XML bytes in `data`:

```python
import base64
import json
from pathlib import Path

request = {
    "module": "gpx_import",
    "filename": "observations.gpx",
    "data": base64.b64encode(Path("observations.gpx").read_bytes()).decode("ascii"),
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

The response contains `results.Object`; module errors use `error`, including
in HTTP 200 responses. The module does not save the result to a MISP event.
It needs PyMISP's `gpx` v1 and `geolocation` v8 templates, already included in
the project's minimum PyMISP version. There are no additional dependencies or
network lookups.

| GPX source | MISP representation |
| --- | --- |
| Original XML bytes | `gpx.attachment`, with filename, MIME type, size, MD5, SHA1 and SHA256 |
| Root and dataset metadata | GPX version, creator, name, description, author name, time, keywords and links |
| Dataset geometry | Waypoint, route, track, segment and total point counts; bounds computed from points |
| Route/track point times | Earliest `start-time` and latest `end-time` |
| Each `wpt`, `rtept`, `trkpt` | A `geolocation` with latitude, longitude, EPSG 4326 and WGS84 reference |
| Point elevation and time | `altitude` and equal `first-seen`/`last-seen` attributes |
| Point name, comment, description, source, symbol and type | Labelled lines in `geolocation.text` |
| Point position in dataset | Object comment and a `contains` reference from the `gpx` object |

All attributes have `to_ids=false`: these are geographic observations. Repeated
coordinates remain separate observations, retaining their times and positions.
Timestamps with offsets are normalized to UTC; timestamps without offsets are
interpreted as UTC. Coordinates retain their decimal precision. Latitude must
be in [-90, 90] and longitude in [-180, 180), as in the GPX schema.

Unknown metadata and vendor extensions remain in the original attachment.
They are not independently converted to MISP attributes. Declared bounds are
not used to override observed coordinates. Empty datasets still produce a
`gpx` object. `filename` defaults to `import.gpx`; directory components are
removed, and no client-supplied filesystem path is opened.

Input is limited to 20 MiB, 10,000 points and 32 XML nesting levels. Compressed
files, DTDs and entity declarations are unsupported. Malformed XML, unsupported
versions/namespaces and invalid point coordinates, elevations or times reject
the entire import. This is a GPX field parser, not full XSD validation.
