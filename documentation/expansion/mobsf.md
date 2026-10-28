# MobSF

The `mobsf` expansion module integrates MISP with a
[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
instance. It retrieves existing static analysis by MD5, or uploads an attachment
or MISP malware sample and starts static analysis. Android, iOS and Windows
packages are supported according to the installed MobSF version and its configuration.
Dynamic analysis requires device setup and is outside this module's scope.

Enable `Plugin.Enrichment_mobsf_enabled` in MISP and configure:

| Setting | Default | Purpose |
| --- | --- | --- |
| `url` | Required | MobSF base URL, such as `https://mobsf.example` or `https://example.org/mobile`. Do not append `/api/v1`. |
| `apikey` | Required | MobSF API key, sent directly in the `Authorization` header. |
| `timeout` | `120` | Request timeout in seconds, from 1 to 3600. Synchronous scans can take several minutes. |
| `max_size_mb` | `50` | Maximum decoded container and unpacked sample size, in MiB, from 1 to 500. |

Settings use the `Plugin.Enrichment_mobsf_` prefix, for example
`Plugin.Enrichment_mobsf_url`. HTTPS certificate verification stays enabled;
HTTP is supported for local deployments. Redirects and automatic retries are disabled.

An `md5` input calls `POST /api/v1/report_json` with `hash`. It does not upload
anything or start a scan. MobSF uses MD5 as its scan identifier; SHA1 and SHA256
are extracted from reports but are not accepted as lookup inputs. A missing or
unfinished report returns an error explaining that no completed report was found.

An `attachment` input sends the decoded bytes and filename to
`POST /api/v1/upload`, verifies the returned MD5 against the supplied bytes, then
calls `POST /api/v1/scan` with `hash`. A `malware-sample` input first unpacks the
MISP ZIP using the standard `infected` password, skips `.filename.txt` metadata,
requires exactly one sample, enforces the unpacked size limit and checks the
MD5 in `filename|md5`. Application ZIP attachments remain intact.
Submissions send the sample to the configured instance under its analysis and
sharing policies. After a timeout, check MobSF before submitting again.

Synchronous scan responses are parsed immediately. MobSF instances with
asynchronous analysis return a task receipt (including already scheduled tasks
whose `task_id` is null). The module returns this receipt and the sample MD5
without polling. Expand that MD5 after analysis completes to retrieve the report.

Results use the existing `sandbox-report`, `file`, `android-app` and `software`
object templates. The sandbox report contains the full JSON response and a link
that lets MobSF select the appropriate platform's report view. Files carry the
available hashes and filename. Android reports carry the app ID and name; iOS
and Windows reports carry software name and version when available. Platform
specific findings, permissions, certificates and bundle metadata remain in the
full report. Domains, URLs and email addresses are extracted and deduplicated.
Extracted attributes have `to_ids=false`: their presence in an application does
not establish that they are malicious. Objects reference the original attribute,
whose metadata is preserved. No new object template is required.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "mobsf",
  "attribute": {
    "type": "md5",
    "value": "d41d8cd98f00b204e9800998ecf8427e",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "url": "https://mobsf.example",
    "apikey": "YOUR_MOBSF_API_KEY"
  }
}
```

For submission, replace the attribute with `type: "attachment"`, the actual
package filename as `value`, and its base64 content in the attribute's `data` field.
Tests mock the API; they do not submit real applications to MobSF.
