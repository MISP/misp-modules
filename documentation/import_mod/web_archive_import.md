# Portable web archive evidence import

Select **Portable Web Archive Evidence Import** in MISP's file import UI.
API clients can send a base64 file in `data` to `POST /query` with the module
name `web_archive_import`. The importer accepts UTF-8 HAR 1.1 and 1.2, WARC 1.0
and 1.1 including concatenated gzip streams, and WACZ packages containing local
WARC members. It reads the uploaded bytes offline.

## Captures and provenance

For HAR, the importer creates a `har-entry` and linked `page-capture` for each
HTTP(S) exchange. It preserves the request URL and method, the original request
start time and its normalized UTC value, the response status and reported HTTP
version, and selected response headers. Status `0` records a request with a
missing response. The capture's `archive-record-id` is a JSON Pointer such as
`/log/entries/0`, using the entry's original zero-based array index. All entries
contribute to the scanned count.

For WARC and WACZ, the importer creates a `warc-record` and linked
`page-capture` for each HTTP(S) response, revisit, or resource record. It
preserves the recorded URL, record ID, original date text, WARC block length,
and uncompressed byte offset. WACZ records also carry the ZIP member path.
Revisit records preserve the required profile URI and any supplied reference
ID, target URI, and date for the earlier capture.
Dates that include seconds also get a normalized UTC value. The raw date retains
the source precision. Truncation markers and declared WARC digests are retained
when present.
Request records and other WARC record types contribute to the scanned count.

The importer retains status, HTTP version, and selected headers from archived
response blocks and standard revisit profiles. Revisit records with other
profiles retain their WARC metadata. In all supported formats, selected HTTP
headers include content type, size and encoding, redirect location, date, last
modification, ETag, language, transfer encoding, cache controls, and `Vary`.
Each header is a separate `{name, value}` JSON attribute. Bodies, request
headers, and cookies stay in the original archive. Importing the archive never
renders pages or follows URLs or redirects. Imported attributes have IDS
matching and automatic correlation disabled.

The root `file` object records the upload's SHA-256, byte count, and filename.
The links let an analyst trace a page capture through its HAR entry or WARC
record to that file. Enable **Attach the original archive** or set
`config.include_archive` to `true` to retain the original upload as an
attachment. Apply the case's sharing controls to URLs, selected metadata, and
original attachments.

## WACZ integrity checks

A WACZ must include root `datapackage.json` and at least one WARC under
`archive/`. The importer checks the manifest's resource list against the ZIP
files. Every supplied resource byte count and SHA-256 is checked against its
member bytes, including the compressed bytes of `.warc.gz` members. Legacy
nested `stats` declarations with SHA-256 are supported. When
`datapackage-digest.json` is present, its SHA-256 must match the exact manifest
bytes. A mismatch or unsupported declared digest causes the upload to fail.

Results record the manifest digest status, the number of resources with
verified digests, and the presence of signature metadata. Signature
authentication and WARC block or payload digest verification are outside these
checks. Declared WARC digests remain available for later verification.

## Limits

An upload can contain up to 25 MiB of input, 512 ZIP members, 128 MiB of inflated
ZIP members, and 128 MiB of expanded WARC across all members. The importer scans
up to 10,000 WARC records or HAR entries and returns up to 1,000 captures. WARC
and HTTP headers are bounded, with up to 64 selected headers per capture and
8 MiB of capture metadata in total. Split larger archives before uploading.

- [HAR specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
- [WARC 1.1 specification](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/)
- [WACZ specification](https://specs.webrecorder.net/wacz/1.2.0/)
- [WACZ signing and verification specification](https://specs.webrecorder.net/wacz-auth/0.1.0/)
