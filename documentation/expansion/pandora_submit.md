# Pandora Submit

The `pandora_submit` expansion module submits an `attachment` or `malware-sample`
to [Pandora](https://github.com/pandora-analysis/pandora). It uses
`https://pandora.circl.lu` when no instance URL is configured and returns an
External analysis `link` attribute. Analysis runs asynchronously; open the link
to see its status and results.

Enable `Plugin.Enrichment_pandora_submit_enabled` in MISP's server settings.
All module configuration settings are optional:

| Setting | Default | Purpose |
| --- | --- | --- |
| `url` | `https://pandora.circl.lu` | Instance base URL, including a path prefix if needed; for example `https://pandora.example/pandora`. Do not append `/submit`. |
| `apikey` | Empty | Pandora API key, sent directly in the `Authorization` header without a Bearer prefix. Leave empty for anonymous submission on instances that allow it. |
| `timeout` | `30` | Positive integer request timeout in seconds. |
| `validity` | `0` | Nonnegative integer lifetime of the report access seed in seconds. `0` creates a link without expiry; `86400` makes it valid for one day. |
| `password` | Empty | Password passed to Pandora to decrypt the submitted file, such as a password protected attachment. |

In MISP these settings use the `Plugin.Enrichment_pandora_submit_` prefix, for
example `Plugin.Enrichment_pandora_submit_url`.

The sample is uploaded to the selected instance. The returned link includes an
access seed: anyone with that link can view the report while the seed is valid,
subject to the instance's permissions and retention policy. HTTPS certificate
verification remains enabled. HTTP URLs are supported for local deployments.

For `malware-sample` attributes, the module decodes the base64 data and unpacks
MISP's ZIP container locally using the standard `infected` password. It skips
directory entries and `.filename.txt` metadata and requires exactly one sample.
The original filename (before `|md5`) and extracted bytes are sent to Pandora.
Attachments are submitted as supplied; ZIP attachments are not unpacked locally.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "pandora_submit",
  "attachment": "example.txt",
  "data": "SGVsbG8gUGFuZG9yYQo=",
  "config": {
    "url": "https://pandora.example/pandora",
    "apikey": "YOUR_PANDORA_API_KEY",
    "validity": "86400"
  }
}
```

Omit `config` entirely to use the public CIRCL instance anonymously with the
defaults. The module uses Pandora's multipart `POST /submit` API with the
`validity` query parameter and builds the report URL from the returned `taskId`
and `seed`, preserving the configured instance path. It does not poll, follow
redirects or automatically retry submissions. After a timeout, check the instance
before resubmitting, since the analysis may already have been created.

The module uses the existing `requests` dependency; no additional package or
MISP credentials are required. Tests mock transport and do not submit any files
to a live Pandora instance.
