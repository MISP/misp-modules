# Google Cloud Audit Logs Import

Select **Google Cloud Audit Logs Import** (`google_cloud_audit_import`) in
MISP's file import interface. The module reads an operator-supplied UTF-8
JSON file, optionally compressed with gzip. It accepts a single Cloud
Logging `LogEntry`, a JSON array from `gcloud`, and a saved Logging API
`entries.list` response. If a response reports another page, import the
other saved pages separately. [Logging API response schema](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)

Save a project's audit entries with `gcloud`.

```sh
gcloud logging read 'logName:"cloudaudit.googleapis.com"' \
  --project=PROJECT_ID --limit=1000 --format=json > google-cloud-audit.json
```

The importer recognizes Admin Activity, Data Access, System Event, and
Policy Denied logs. Entries use native audit log names and
`google.cloud.audit.AuditLog` payloads. The scope comes from `logName`.
A project ID in the monitored resource labels is recorded separately.
[Google Cloud audit log format](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs)

## Imported evidence

- Each `google-cloud-audit-event` records the principal email and subject,
  service, method, reported resource, log category, operation identifiers
  and caller context where supplied. It preserves reported caller labels such
  as `gce-internal-ip`, with a separate IP attribute when the value is a valid
  address. It retains the original timestamps and projects UTC datetime
  values at microsecond precision for the MISP timeline. The importer reports
  missing event timestamps and keeps reception time in its own attribute.
- Each reported `authorizationInfo` entry becomes a linked
  `google-cloud-authorization-check`. This keeps the permission and resource
  paired with their `granted`, `denied`, or `unknown` decision. An absent
  `granted` value yields `unknown`. The overall operation's explicit
  `google.rpc.Status` code lives on the parent event.
- Each reported IAM `bindingDeltas` entry becomes a linked
  `google-cloud-iam-binding-change`. It records its action, role, member, and
  available condition fields. The importer reads deltas from
  `protoPayload.metadata.policyDelta` and the legacy
  `protoPayload.serviceData.policyDelta`. The link cites the original JSON
  path. [Google Cloud IAM policy history](https://docs.cloud.google.com/iam/docs/review-iam-policy-history)

The import links events to a `file` object containing the SHA-256 of the exact
uploaded bytes, including compression, and identifies the record position
in that file. Enable **Attach the exact source audit log** to keep the
original file. Request and response bodies, free-text status messages,
and arbitrary service metadata are available through the optional original
attachment. Generated attributes have IDS and correlation disabled.

Events with both an `insertId` and an event timestamp use the native scope,
log category, full event time, and ID as their stable identity. Identical
repeats in an upload count once. Conflicting entries for the same identity
produce an error. Entries missing either field retain their individual positions.

Uploads accept up to 10 MiB of input, 20 MiB after decompression, 1,000 events,
and 2,000 authorization checks, binding deltas, and delegation entries
combined. Install the companion templates for use in MISP.

## Module API

```json
{
  "module": "google_cloud_audit_import",
  "filename": "google-cloud-audit.json.gz",
  "data": "<base64 file>",
  "config": {"include_source": false}
}
```
