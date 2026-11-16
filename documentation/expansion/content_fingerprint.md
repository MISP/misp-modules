# Content fingerprint

`content_fingerprint` fingerprints supplied text, raster images and video
offline. It returns exact SHA-256 hashes, versioned approximate fingerprints
and reproducibility metadata. An optional reference item produces pairwise
similarity evidence for copied articles, altered images and reused video clips.

Text requires only the project's existing Python dependencies. Images and
video require **FFmpeg and ffprobe 5 or later** on the service user's PATH
(`apt install ffmpeg` on Debian/Ubuntu). No content is uploaded or fetched.
Install the bundled `misp_modules/data/content-fingerprint/definition.json`
template on the MISP server to render and edit the custom object's fields.

## Input and comparison

Expand a `text` attribute or a base64 `attachment`, with `type`, `value` and
`uuid`. For attachments, `value` is the filename and `data` holds the bytes.
Top-level `data` is also accepted for the source attachment.

```json
{
  "module": "content_fingerprint",
  "attribute": {
    "type": "text",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    "value": "The research team published an article about the ancient forest and its rare plants."
  },
  "reference": {
    "type": "text",
    "uuid": "b3936b7a-f6f1-4aa5-8d26-41f2e602af00",
    "value": "The research team published an article about the ancient forest and its unusual plants."
  }
}
```

Omit `reference` to generate fingerprints only. The reference must be a full
attribute with a different UUID and the same detected content type. It may
also be supplied as an attribute object or a JSON string in `config.reference`,
which supports clients exposing only module configuration. Reference
attachments require their own base64 `data`. Both source attributes and their
metadata are preserved in the result.

| Configuration | Default | Meaning |
| --- | --- | --- |
| `content_type` | `auto` | `text`, `image`, `video` or `auto`; applies to source and reference. Auto uses attribute type, recognised attachment extensions and common media signatures, otherwise text. |
| `reference` | unset | Optional comparison attribute object or its JSON representation. Top-level `reference` takes precedence. |
| `sample_interval` | `1` | Integer 1–60 seconds between selected video frames. |
| `max_frames` | `120` | Integer 2–300; maximum retained frames per video. An extra frame detects truncation. |
| `timeout` | `60` | Integer 1–120 seconds shared by media subprocesses for both inputs. |

Text attachments must contain UTF-8, optionally with a BOM. Article extraction
from HTML and OCR are outside this module: supply the article's text. Raster
formats include PNG, JPEG, WebP, BMP, TIFF and GIF; only the first image frame is
used. Video containers include MP4/MOV, Matroska/WebM and AVI. Other formats
return a decoding error rather than enabling arbitrary demuxers. Animated
images can be explicitly treated as video for sampled-frame analysis.

## Fingerprints and versions

Every input has an exact `sha256` of the original bytes. For text attributes,
these are the UTF-8 bytes of `value`. SHA-256 is identified as FIPS 180-4.
Re-encoding an image or video generally changes this hash.

Text also has:

- A normalised SHA-256: decode UTF-8-sig, apply Unicode NFKC and casefold,
  extract Unicode word tokens excluding underscores, and join with ASCII spaces.
  Punctuation, case and spacing differences therefore disappear.
- A 64-bit SimHash over **distinct five-word shingles**. Each shingle is hashed
  with SHA-256, using its first eight bytes as a big-endian feature. Bits vote
  with equal weight; ties produce a one. The hexadecimal value has 16 digits.
- The normalisation and SimHash versions, including Python's Unicode database
  version (`v1-u…`), token counts, shingle counts and all parameters.

Empty token streams have no normalised fingerprint. Text with fewer than
three distinct five-word shingles retains any computable SimHash in metadata,
marked unusable for approximate decisions and omitted from correlation keys.

Images and selected video frames use **`phash63-dct32-v1`**, this module's
specified perceptual-hash variant, rather than an undocumented claim of
compatibility with every pHash implementation:

1. Decode the first visual stream with FFmpeg's default autorotation.
2. Convert to RGBA and premultiply alpha onto black, resize to 32×32 with the
   area scaler, then convert to the `gray` pixel format.
3. Calculate DCT-II coefficients, using the orthogonal factors of `1/sqrt(2)`
   for zero-frequency axes. Use the top-left 8×8 coefficients.
4. Exclude DC, take the median of the remaining 63 coefficients and set bits
   strictly greater than that median. Serialise row-major, MSB-first in 16 hex
   digits, with the DC bit fixed to zero: **63 effective bits**.

The full FFmpeg version string, preprocessing description, dimensions, codec,
parameters, per-frame hashes and actual presentation timestamps are retained.
Frame sampling chooses the first frame, then the next frame at least
`sample_interval` seconds after the previous selection. It uses presentation
timestamps rather than assuming a constant frame rate. Audio is excluded.
Frames with luma standard deviation below 5 after preprocessing remain in the
report but are unusable for approximate matching and correlation; this avoids
matching uniform blank frames.

## Similarity evidence

A reference adds an `annotation` object containing a JSON comparison report,
linked to both fingerprint objects. Exact-byte equality is reported separately
as `exact_match`. Approximate decisions use explicit heuristic thresholds:

| Content | Evidence and decision |
| --- | --- |
| Text | SimHash Hamming distance ≤10 **and** exact shingle Jaccard similarity ≥0.5; both items must have at least three distinct shingles. Includes shared-shingle count, up to five matching examples and normalised equality. |
| Image | Perceptual Hamming distance ≤10 of 63 bits, with both frames usable. Includes the matching frame pair and measured distance. |
| Video | Longest consecutive, order-preserving run of frame pairs with Hamming distance ≤10. At least two pairs are required; differences in consecutive timestamp steps may be at most 25% of the configured sample interval. Includes each matched pair's indices, timestamps and distance, exposing the clip's offset in each input. |

Media comparisons require matching fingerprint and decoder versions. These
scores are content evidence, not probabilities or attribution. Approximate
matches can result from common templates, scenes or graphics; unrelated images
can collide. Small image changes and re-encoding often preserve perceptual
hashes, but heavy crops, rotations, overlays and substantial meme edits can
defeat them. The module does not recognise the semantic meaning of an image.
Video matching is sampling-based: very short excerpts, speed changes, edits
between sample points and sampling-grid shifts may be missed. It compares the
supplied pair, without querying a remote similarity index.

## MISP output and limits

The response is `misp_standard`. Each source has a `content-fingerprint`
object referencing its original attribute via `fingerprint-of`:

- `sha256`: original-byte exact hash, with correlation enabled.
- `content-type`: detected `text`, `image` or `video`.
- `fingerprint`: algorithm/version-qualified keys for normalised text hashes,
  usable SimHashes or usable frame hashes, deduplicated within the object.
- `metadata`: the complete JSON fingerprint report, with `schema_version=1`.

MISP's ordinary correlation finds **equal** keys. It does not automatically
calculate Hamming distances: use the optional reference comparison for
approximate evidence. Metadata and content-type correlation are disabled;
all derived attributes use `to_ids=false`. Frame timestamps remain in metadata
even when repeated hashes share one correlation attribute.

Inputs are limited to 50 MiB each; decoded text to 2 MiB and 100,000 tokens;
media to 16 million pixels per frame. Local subprocess output and diagnostics
are checked every 20 ms against a 1 MiB limit, with a shared deadline and
process termination on excess. Bursts can overshoot between checks. FFmpeg is
restricted to local input protocols and the listed demuxers.

Videos exceeding `max_frames` return the retained prefix with
`media.truncated=true`; comparisons include both truncation flags. This is
explicitly partial coverage, not a claim about the unsampled remainder.
Missing tools, corrupt input, unsupported media and exceeded hard limits
return an error instead of fabricated or silently incomplete fingerprints.
