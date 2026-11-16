# Website tracker extract

`website_tracker_extract` extracts analytics, advertising, affiliate publisher
and site-verification identifiers from captures already held by the analyst.
It runs offline and needs no API key or additional dependencies beyond PyMISP.
Captured HTML, scripts and HAR exports from LookyLoo or other capture tools can
be supplied directly. The LookyLoo API modules remain useful for capture lookup
and enrichment.

## Input

Expand a `text` attribute containing HTML, JavaScript or HAR JSON, or an
`attachment` attribute containing the captured file with base64 `data`:

```json
{
  "module": "website_tracker_extract",
  "attribute": {
    "type": "text",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    "value": "<script>gtag('config', 'G-ABC1234567');</script>"
  }
}
```

For attachments, `value` is the filename. The module accepts `data` inside the
attribute or at the request's top level. The legacy `attachment` filename plus
top-level `data` request is also supported; it creates a source attachment UUID
because that request format has none. Standard attributes require a valid UUID
and preserve their metadata and detection flag.

HAR is detected from a JSON `log` object, or required for `.har` attachments.
The module reads `log.entries[].request.url`, `request.postData.text` and
`response.content.text`. Embedded text, JavaScript, JSON, XML and form bodies
are scanned, including base64 response bodies. Missing bodies and declared
binary MIME types are skipped. UTF-8 BOMs are removed; invalid UTF-8 bytes are
replaced during decoding. Capture text is never executed and resource URLs are
never fetched.

## Supported identifiers

| Provider | Recognised evidence |
| --- | --- |
| Google Analytics | `UA-…` property IDs |
| Google Analytics 4 | `G-…` measurement IDs |
| Google Tag Manager | `GTM-…` container IDs |
| Google Ads | `AW-…` advertiser IDs, excluding conversion labels |
| Google AdSense | `pub-…` and `ca-pub-…`, normalised to `pub-…` |
| Meta Pixel | `fbq('init', '…')`, `facebook.com/tr` URL/form `id` |
| Hotjar | `hjid` configuration field |
| Yandex Metrica | `ym(…, 'init')`, `Ya.Metrika` / `Ya.Metrika2`, `mc.yandex.ru/watch/…` |
| Microsoft Clarity | Standard bootstrap invocation, `setProjectId`, `clarity.ms/tag/…` |
| LinkedIn Insight | `_linkedin_partner_id` assignment |
| TikTok Pixel | `ttq.load('…')` |
| Amazon Associates | `amzn_assoc_tracking_id`, `tag` on recognised Amazon store domains |
| Awin | `awinaffid` on `awin1.com` |
| ShareASale | Publisher `u` on `shareasale.com/r.cfm` |
| Google, Facebook, Bing verification | `google-site-verification`, `facebook-domain-verification`, `msvalidate.01` meta tags |

HTML query entities, percent-encoded query values and common JavaScript URL
escapes (`\/`, `\u0026`, `\x26`) are handled. Generic IDs, arbitrary affiliate
parameters, click IDs such as `gclid` / `fbclid`, and tracker hostnames alone
do not create identifier objects. Ambiguous numeric URL parameters require a
recognised provider host, including its subdomains.

## Output and correlation

The result uses `misp_standard` and the existing `tracking-id` object template.
There is one object per provider/identifier pair, with all sightings retained.
Each object references the source attribute through `extracted-from`.

- `id` is a provider-qualified correlation key, for example
  `meta-pixel:12345678`. Numeric IDs belonging to different providers therefore
  do not correlate accidentally. AdSense's optional `ca-` prefix is removed.
- `tracker` contains the provider name.
- `description` contains JSON with `category`, the raw normalised `identifier`
  and a `sources` list.
- `url` holds the containing HAR entry's request URL when available. A script
  body is attributed to the script resource, rather than to an assumed page.

All extracted attributes use `to_ids=false`; only `id` permits correlation.
Provider names, descriptions and resource URLs have correlation disabled.
Object UUIDs are stable for the same source UUID and correlation key.
No matches return the source attribute and an empty object list.

For example, a description may contain:

```json
{
  "category": "analytics",
  "identifier": "G-ABC1234567",
  "sources": [
    {
      "source": "log.entries[2].response.content.text",
      "line": 1,
      "column": 16,
      "offset": 15,
      "url": "https://publisher.example/script.js"
    }
  ]
}
```

`source` is the attachment filename, `text`, or the HAR field's JSON path.
Lines and columns are one-based; offsets are zero-based Unicode character
offsets in that decoded field, rather than byte offsets in the HAR file.
Script/prefix rules locate the identifier. URL rules locate the start of the
URL; verification rules locate the meta tag; HAR form rules locate the start
of the form body. Different sightings of one ID remain separately located.

## Limits and interpretation

Input is limited to 10 MiB, HAR to 2,000 entries and 20 MiB of decoded text
bodies, and results to 10,000 distinct located sightings. Invalid HAR fields,
invalid base64, unsupported body encodings and exceeded limits return an error
instead of silently returning incomplete evidence. A HAR without embedded
bodies can still yield identifiers in its recorded request URLs.

Shared IDs provide site-clustering evidence beyond hosting, but do not prove
common ownership: agencies, copied templates, shared advertising accounts,
third-party scripts and documentation examples can reuse identifiers. These
are observations in captured material, not confirmation that a tracker ran.
The extractor recognises the patterns above; it does not evaluate JavaScript,
resolve shortlinks, deobfuscate arbitrary code or discover IDs constructed at
runtime. Site-local numbers such as a Matomo `siteId` are intentionally omitted
because they need an associated instance URL to form a useful correlation key.
