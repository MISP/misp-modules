# NMEA 0183 import

`nmea_import` accepts ASCII receiver logs containing bare NMEA 0183 sentences,
one per line. It preserves the original bytes in an `nmea` object and extracts
GGA, RMC and GLL positions as linked `geolocation` objects. All generated
attributes have `to_ids=false`. No network access or additional dependency is
required. The new [`nmea` v1 template](https://github.com/MISP/misp-objects/pull/582)
is bundled with the module so existing
PyMISP installations can use it; install that template in MISP's object catalog
for the corresponding editor and display support.

Upload the log or paste its text in MISP's import interface. For `/query`,
base64-encode the original bytes:

```python
import base64
import json
from pathlib import Path

request = {
    "module": "nmea_import",
    "filename": "receiver.nmea",
    "data": base64.b64encode(Path("receiver.nmea").read_bytes()).decode("ascii"),
}
Path("request.json").write_text(json.dumps(request), encoding="utf-8")
```

```sh
curl --fail --silent --show-error -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

The response contains `results.Object`; errors use `error`, including in HTTP
200 responses. The module does not save results to a MISP event.

| Source | MISP representation |
| --- | --- |
| Original log | `nmea.attachment`, filename, MIME type, byte size, MD5, SHA1 and SHA256 |
| All sentences | Total count, sentence types and standard talker IDs |
| GGA/RMC/GLL with a valid fix | Separate linked geolocations; repeated observations remain distinct |
| Invalid/no-fix position sentences | `invalid-fix-count`, with the full sentences retained in the attachment |
| Other sentence types | `unhandled-sentence-count`, with payloads retained in the attachment |
| Extracted coordinates | Dataset minimum/maximum latitude and longitude |
| Dated position observations | Dataset `start-time`/`end-time`; observation `first-seen` and `last-seen` |
| Receiver quality, speed and source context | JSON in each geolocation's `text` attribute |

GGA context includes fix quality, satellites, HDOP, mean-sea-level altitude,
geoid separation, differential-correction age and reference station ID when
available. RMC context includes status, mode, speed in knots, course in degrees
and navigation status when available. Every observation records its talker,
sentence type, source line number, UTC time-of-day and original sentence.
HDOP is dimensionless and is not converted to `accuracy-radius`.

## Position, altitude and fix status

Latitude is `ddmm.m...`; longitude is `dddmm.m...`. The module converts degrees
and minutes using decimal arithmetic at 40 significant digits and applies N/S
and E/W signs. The original decimal text remains in the attachment. WGS84 is
assumed unless a DTM sentence explicitly says otherwise; non-W84 DTM records
reject the log. No reprojection is performed. Coordinates must fall within
[-90, 90] latitude and [-180, 180] longitude, with minutes below 60.

GGA altitude is above mean sea level. A geolocation's ellipsoid `altitude` is
created only when both that height and geoid separation are present in metres:
**ellipsoid height = MSL height + geoid separation**. If either is missing,
height fields remain in the observation's context without inventing an
ellipsoid altitude.

GGA quality 0, RMC/GLL status V, position mode N and RMC navigation status V
produce no geolocation. Their stale or empty position fields are not parsed.
Quality codes 1–8 and active modes are retained as reported, including dead
reckoning, manual input and simulation; their presence is not interpreted as a
confidence assessment. The module does not fuse GGA, RMC and GLL sentences into
one fix or infer a physical receiver identity from a talker ID.

## Dates and UTC

RMC dates use `ddmmyy`, with a fixed century rule: 80–99 mean 1980–1999;
00–79 mean 2000–2079. ZDA supplies a full year. Only active RMC fixes and valid
ZDA sentences establish a date. ZDA's local-zone fields do not shift its UTC.

Subsequent GGA/GLL observations use the last dated context for the **same talker**.
The time-of-day is placed on the nearest day relative to the preceding dated
observation: a difference greater than 12 hours adjusts the day forward or
backward. This supports midnight/year rollover and slightly out-of-order
sentences near midnight. It assumes a continuous stream with gaps shorter than
12 hours; it cannot resolve sparse multi-day logs from time-of-day alone.

Dates are not backfilled before the first dated sentence, shared across talker
IDs, or taken from the host clock, filename or file modification time. Undated
positions retain their UTC time in `text` without datetime attributes, with a
response warning. This also applies to GGA/GLL-only logs. UTC fractions support
up to six digits; leap-second `ss=60` values are currently unsupported.

## Framing and limits

Checksums are mandatory and validated for **every** sentence, including unknown
and proprietary ones. Hexadecimal checksum letters can use either case.
CRLF, LF and CR line endings are supported and preserved, as are blank lines
and a missing final newline. Proprietary `$P...` messages, other standard
sentences and `!` encapsulation messages such as AIS are retained without
payload decoding. This is GNSS extraction, not an AIS decoder or a complete
NMEA sentence implementation.

Input is limited to 20 MiB, 100,000 lines including blank lines, 10,000 extracted
positions and 1,024 characters per nonblank sentence. Numeric fields support
at most 32 characters; coordinate minute fractions support up to 24 digits.
Compressed files, timestamp prefixes, tag blocks, binary receiver protocols,
missing/bad checksums, non-ASCII text and malformed supported fields reject
the entire import. Errors include the source line when available.

The filename defaults to `import.nmea`; path components are removed, and no
client-supplied path is opened. Logs containing only unsupported sentences or
invalid fixes still produce a dataset; empty/blank logs are rejected.
