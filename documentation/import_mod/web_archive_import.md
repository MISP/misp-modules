# Portable web archive evidence import

Select **Portable Web Archive Evidence Import** in MISP's file import UI.
API clients can send a base64 file in `data` to `POST /query` with the module
name `web_archive_import`. The importer accepts WARC 1.0 and 1.1, including
concatenated gzip streams, and WACZ packages containing local WARC members.
It reads the uploaded bytes offline.

## Captures and provenance

The importer creates a `warc-record` and linked `page-capture` for each HTTP(S)
response, revisit, or resource record. It preserves the recorded URL, record ID,
UTC capture time and original date text, WARC block length, and uncompressed
byte offset. WACZ records also carry the ZIP member path. Revisit references,
truncation markers, and declared WARC digests are retained when present.
Request records and other WARC record types contribute to the scanned count.

Where the WARC contains an archived HTTP response header block, the importer
retains the status, HTTP version, and selected headers. These include content
type, size and encoding, redirect location, date, last modification, ETag,
language, transfer encoding, cache controls, and `Vary`. Each header is a
separate `{name, value}` JSON attribute. Bodies, request headers, and cookies
stay in the original archive. Importing the archive never renders pages or
follows URLs or redirects. Imported attributes have IDS matching and automatic
correlation disabled.

The root `file` object records the upload's SHA-256, byte count, and filename.
The links let an analyst trace a page capture through its WARC record to that
file. Enable **Attach the original archive** or set `config.include_archive`
to `true` to retain the original upload as an attachment. Apply the case's
sharing controls to URLs, selected metadata, and original attachments.

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
up to 10,000 records and returns up to 1,000 captures. WARC and HTTP headers are
bounded, with up to 64 selected headers per capture and 8 MiB of capture metadata
in total. Split larger archives before uploading.

- [WARC 1.1 specification](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/)
- [WACZ specification](https://specs.webrecorder.net/wacz/1.2.0/)
- [WACZ signing and verification specification](https://specs.webrecorder.net/wacz-auth/0.1.0/)
