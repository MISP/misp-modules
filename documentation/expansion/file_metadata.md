# File and media metadata

Run `file_metadata` on an existing MISP attachment, or select **File and Media
Metadata Import** (`file_metadata_import`) to upload one file directly into an
event. Both modules run ExifTool on the MISP modules server. They read the
supplied bytes locally without fetching URLs or embedded references.

## Setup and coverage

Install ExifTool 13.00 or later on the modules service's `PATH`, with Perl
`Archive::Zip` for Office Open XML and OpenDocument properties. Use a current
ExifTool release to get its latest format support and fixes. Install or
refresh the companion `file-metadata` object template on the MISP server.
[ExifTool documentation](https://exiftool.org/)

The extractor accepts formats ExifTool can read, including JPEG, TIFF, PNG,
HEIC, WebP and camera RAW images, XMP sidecars, PDF, Office and OpenDocument
files, and MP4, MOV, Matroska, AVI, MP3, FLAC, WAV and other audio and video
containers. Available tags depend on the format, the file contents and the
installed parser. The `scan_embedded` option enables ExifTool's `-ee3` mode for
additional subdocument and timed-stream metadata where supported, such as
GPS tracks and H.264 supplemental metadata. Set it in the expansion module's
configuration or in the import form.

## Evidence and interpretation

- The `file` object records the supplied basename, SHA-256 of the exact input
  bytes, byte length and detected MIME type when available. The expansion
  links it to the existing attachment. The import can store an exact copy
  of the upload in the file object via `include_original`, which defaults
  to off.
- A linked `file-metadata` object records the parser name and version,
  extraction profile, detected format and source SHA-256. Each tag's value
  is stored as JSON with its fully grouped ExifTool tag name, preserving
  available namespace, document and duplicate-instance groups and the
  original array or object structure. Values are ExifTool's output before
  print conversion. Preserve the original file to retain the on-disk
  representation.
- Recognized embedded time and location tags are marked `unverified` and
  require independent corroboration. Timestamp claims keep the raw value,
  its apparent precision and whether it carries an explicit offset. Missing
  offsets stay unspecified, including for QuickTime dates. Tags containing
  separate offset or subsecond fields are retained independently. No location
  or date is promoted to a confirmed event fact.
- Generated composite tags, temporary-file system metadata and binary payload
  extraction are excluded. Results report when limits omit tags or when
  ExifTool emits a diagnostic. All generated attributes have IDS and
  correlation disabled. Metadata may contain sensitive personal details
  such as coordinates, author names and device identifiers.

Each request accepts up to 64 MiB of decoded input and allows up to 30 seconds
for ExifTool. The module emits at most 4,096 textual or structured tags, with
limits of 32 KiB per serialized tag and 4 MiB of serialized tag values in
total. Set MISP and proxy upload limits to accommodate the base64 request
when working with larger files.

## Module API

Expansion requests carry the original attribute UUID and attachment data.

```json
{
  "module": "file_metadata",
  "attribute": {
    "type": "attachment",
    "uuid": "d2f0b2d5-96ef-49be-9005-2619b600c413",
    "value": "photo.jpg",
    "data": "<base64 file>"
  },
  "config": {"scan_embedded": false}
}
```

Import requests take an optional filename and the file bytes.

```json
{
  "module": "file_metadata_import",
  "filename": "recording.mp4",
  "data": "<base64 file>",
  "config": {"scan_embedded": true, "include_original": false}
}
```
