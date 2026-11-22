# Okta System Log Import

Select **Okta System Log Import** (`okta_system_log_import`) in the MISP file
import interface. The importer accepts a JSON response array saved from the
Okta System Log API (`GET /api/v1/logs`) or an individual native event object.
Gzip-compressed UTF-8 JSON is also supported. Save the response body from
each page and import the files separately or combine their event arrays.
The importer runs locally on the supplied file. [Okta System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog)

## Imported evidence

- Each `okta-system-log-event` records the native `uuid`, event type, actor,
  reported outcome, client address, authentication step and credential
  context. A validated client IP is stored alongside the original address.
  The UTC timeline uses the reported publication time at microsecond
  precision, with the original value kept in its own attribute.
- Each `okta-system-log-target` keeps a reported target's ID, type, alternate
  ID and display name together. Its link and position identify the original
  entry in the event's target array. When all four fields are empty or absent,
  the importer skips that entry and reports the count. Other targets keep
  their original array positions.
- Transaction, external session and root session IDs have separate
  attributes. A transaction groups related activity within an operation.
  An external session groups activity within one session. A root session
  can connect several sessions, including actions by a system actor
  on behalf of a user. [Okta event correlation](https://developer.okta.com/docs/reference/system-log-query/#event-correlation)

Within an upload, an event can link to the first record with the same
concrete identifier or client IP. An actor ID can also match a target ID.
The reference comment records the shared fields. Matching values describe
shared reported context. The same eligible actor and target IDs,
transaction and session IDs, and validated client IPs support native MISP
correlation across MISP events. Common placeholder values remain available
as source text. All generated attributes have IDS disabled.

Each event links to its position in the source file. The file object
records the SHA-256 of the exact upload. Enable **Attach the exact source
audit log** to preserve the full export, including fields outside the
structured projection. Identical records with the same native `uuid`
count once per upload. Conflicting records for the same ID return an error
for the upload.

Install the companion `okta-system-log-event` and `okta-system-log-target`
templates on the MISP server. An upload accepts up to 10 MiB of input,
20 MiB after decompression, 1,000 records and 2,000 target entries.

## Module API

```json
{
  "module": "okta_system_log_import",
  "filename": "okta-system-log.json.gz",
  "data": "<base64 file>",
  "config": {"include_source": false}
}
```
