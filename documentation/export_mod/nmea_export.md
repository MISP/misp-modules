# NMEA 0183 export

`nmea_export` exports the original attachments of MISP `nmea` objects in a ZIP
archive. Each archive member contains the exact stored log bytes, preserving
checksums, sentence order, unknown/proprietary fields and line endings. It has
no configuration, additional dependencies or network calls.

Send MISP events to the misp-modules `/query` endpoint:

```json
{
  "module": "nmea_export",
  "data": [{
    "Event": {
      "Object": [{
        "name": "nmea",
        "Attribute": [{
          "object_relation": "attachment",
          "value": "receiver.nmea",
          "data": "BASE64_ENCODED_LOG_BYTES"
        }]
      }]
    }
  }]
}
```

Include attachment data when fetching events, for example with PyMISP's
`get_event(event_id, with_attachments=True)`. Bare events, `{"Event": {...}}`
wrappers, legacy wrappers with sibling `Object` arrays and lists of these
events are accepted. Attachments are included regardless of `to_ids`.

The response's `data` is base64-encoded ZIP, with MIME type `application/zip`:

```python
import base64
import json
from pathlib import Path

response = json.loads(Path("response.json").read_text(encoding="utf-8"))
if "error" in response:
    raise ValueError(response["error"])
Path("nmea-logs.zip").write_bytes(base64.b64decode(response["data"], validate=True))
```

Module errors use `error`, including in HTTP 200 responses. Missing active
attachments, missing attachment data or invalid logs reject the entire export.
The parser and checksum requirements match the [importer](../import_mod/nmea_import.md).

Logs remain separate even when multiple datasets are exported. Concatenating
logs could associate one receiver's undated GGA/GLL fixes with another
receiver's dated RMC/ZDA records. ZIP members use unique numeric prefixes and
safe basenames, for example `0001-receiver.nmea` and `0002-receiver.nmea`.
Directory components are removed; characters outside ASCII letters, digits,
dot, dash and underscore become underscores. Basenames are limited to
180 characters. The log contents are unchanged. Unpack the archive before
importing individual logs.

Only `nmea` objects are exported. Standalone geolocation objects do not contain
original receiver sentences and are not converted into fabricated fixes,
quality codes, satellites or checksums. Use GPX or GeoJSON to exchange those
locations. Editing or deleting a derived geolocation does not rewrite its
stored source log. Deleted events, objects and attachment attributes are
excluded; an active dataset with no active attachment is an error.

The export accepts at most 1,000 logs, with 20 MiB decoded source bytes,
100,000 source lines and 10,000 positions in total. Each source also obeys the
importer's limits. The archive is limited to 21 MiB to allow ZIP metadata
alongside the source bytes. No archive is returned on error.
