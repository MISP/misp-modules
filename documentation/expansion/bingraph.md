# binGraph

Create a PNG visualization from an `attachment` or `malware-sample` attribute. The
default image combines Shannon entropy over file offsets, the percentages of
`0x00` and `0xFF` bytes in each window, a byte histogram, and a count-ranked
frequency distribution. SHA-256, file size and overall entropy appear below the
plots. This is a new implementation inspired by
[geekscrapy/binGraph](https://github.com/geekscrapy/binGraph), with attribution to
that project. The repository's AGPL-3.0 license applies.

## MISP integration

The module uses the existing **image** object template
(`ca78ec03-3321-4ed3-9840-9bfd52b91d82`, version 1). **No new template is required.**
The object contains a PNG `attachment`, `filename`, and JSON analysis metadata in
`image-text`. Its `visualizes` reference points to the source attribute UUID. The
original attribute is returned unchanged, including its data and detection flags;
new image attributes have `to_ids=false` and correlation disabled.

Enable the `bingraph` expansion module on your MISP instance after restarting
misp-modules. Open an attachment or malware-sample attribute, choose enrichment,
select binGraph, and import the returned image object. The image is attached to
the event. Inline display depends on the MISP version and interface settings.

## Installation and configuration

The module lives at `misp_modules/modules/expansion/bingraph.py`. Its dependencies
are PyMISP, NumPy, and Matplotlib. PyMISP is already a core dependency; Matplotlib
is included in the repository's `minimal` and `all` extras and installs NumPy.
For an existing runtime environment, install any missing packages using that
environment's Python:

```sh
python -m pip install pymisp numpy matplotlib
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `graph_type` | `all` | `all`: combined PNG; `ent`: entropy only; `hist`: histogram only. |
| `chunks` | `750` | Maximum entropy windows, integer 1–4096. Minimum window size is 256 bytes; the final window may be shorter. |
| `max_size_mb` | `10` | Integer 1–50 MiB. Limits both decoded input and unpacked sample size. |

The JSON request uses the `misp_standard` attribute envelope:

```json
{
  "module": "bingraph",
  "attribute": {
    "type": "attachment",
    "value": "sample.bin",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "data": "AAECAwQFBgcICQ=="
  },
  "config": {"graph_type": "all", "chunks": "750", "max_size_mb": "10"}
}
```

For `malware-sample`, use `filename|md5` and the base64-encoded ZIP as `data`.
Supported ZIP layouts are a legacy single sample member or the current MISP pair
`<md5>` and `<md5>.filename.txt`. The ZIP is read with password `infected`, and
the unpacked sample's MD5 must match the attribute. ZipCrypto and unencrypted
ZIPs are supported; AES-encrypted ZIPs require conversion to the MISP format.
Missing data, empty files, corrupt archives, ambiguous member lists, hash
mismatches and exceeded limits produce module errors. An ordinary `attachment`
containing a ZIP is graphed as ZIP bytes; it is not unpacked automatically.

Analysis runs locally, reads archive members into memory, and never executes or
writes the sample to disk. Rendering uses the headless Agg canvas and a lock for
concurrent module requests. Configure a writable `MPLCONFIGDIR` for the service
if its home directory is read-only.

## Differences from the original tool

This module implements the original tool's entropy and histogram views for MISP,
with fixed PNG dimensions and JSON metadata. Entropy uses bits per byte (0–8),
whereas binGraph normalizes to 0–1. The minimum window size avoids the always-zero
entropy produced by one-byte windows for small files. Short final windows can
still have lower estimated entropy. Ranked histogram counts are a separate line
on the byte axis, with rank indicated in the axis label.

All inputs are treated as binary blobs. PE/ELF sections and entry-point
annotations, arbitrary interesting-byte groups, custom styles, and CLI batch
processing are outside this implementation. High entropy alone is not a malware
verdict. A specialized object template would be useful only if individual
statistics need separately typed, searchable relations; the image object covers
the requested visualization.

## Validation

```sh
python -m pytest -q tests/test_bingraph.py
```

Tests cover real PNG generation in each mode, image object round trips, known
entropy and histogram values, encrypted MISP ZIPs, legacy archives, hash checks,
input and decompression limits, invalid requests, short files and concurrency.
