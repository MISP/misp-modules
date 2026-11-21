# Microsoft identity and audit logs import

Select **Microsoft Identity and Audit Logs Import** in the file import interface.
API clients can submit a base64 file in `data` to `POST /query` with
`module` set to `microsoft_audit_import`. The importer reads saved exports
offline.

## Supported exports

| Source | Input |
| --- | --- |
| Microsoft Entra sign-ins | Native JSON records with `id`, `createdDateTime`, and sign-in fields. |
| Microsoft Entra directory audits | Native JSON records with `id`, `activityDateTime`, and `activityDisplayName`. |
| Microsoft Purview Unified Audit Log | Management Activity API JSON records with `Id`, `CreationTime`, and `Operation`, or a CSV with one such JSON record per `AuditData` cell. |

JSON can be a single record or an array. Microsoft Graph `value` envelopes
are also accepted. If a Graph export indicates another page, the importer
returns a warning. Import additional saved pages separately. Azure Monitor
diagnostic `records` envelopes, Entra CSV, and CSV with flattened `AuditData`
columns need conversion to one of the supported formats.

## Imported observations

Each record becomes an unreviewed `microsoft-audit-event` object. The importer
maps available actor, application, session, correlation, workload, result, and
reported address fields. It keeps directory targets grouped and distinguishes
an application registration ID from a service principal ID. A validated source IP
is recorded separately from the original address, which may include a port.

Entra timestamps require an explicit timezone. A timezone-free Purview
`CreationTime` uses UTC, as specified in the Microsoft schema. The normalized
UTC time is used for the MISP timeline. Original timestamps retain all source
precision, including the seventh fractional digit in Microsoft Graph dates.
An enriched sign-in record can include Log Analytics `TimeGenerated` as its
reported record timestamp. For ingestion time, include `IngestionTime` from an
explicit `ingestion_time()` query projection. Both fields retain their original
values and are normalized independently. [Azure Monitor timestamp definitions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time)

Purview `ResultStatus` is retained as reported. For Entra STS logon records, an
explicit `LogonError` can establish a reported failure. HTTP success in
`ResultStatus` leaves the sign-in outcome unknown. Imported attributes have IDS
matching and automatic correlation disabled.

Supply `config.tenant_id` or the **Optional reporting tenant UUID** setting
when an Entra export omits the reporting tenant. Purview provides it in
`OrganizationId`. The importer checks supplied tenant context against any
tenant in the record. Sign-in home and resource tenants remain distinct fields.
Event UUIDs are stable for the same log type, reporting tenant scope, and
native record ID. An identical repeated record is counted once per upload.
Conflicting records in the same scope cause the upload to fail.

## Source evidence and limits

Every event links to a source file object with a sanitized filename, byte
count, and SHA-256 of the uploaded bytes. The link records the one-based row
or record index. Enable **Attach the exact source log** or set
`config.include_source` to `true` to attach the original. The default mapping
omits raw records, modified properties, workload parameters, and free-text
error details. Review sharing settings before attaching originals.

The module accepts UTF-8 or BOM-marked UTF-16. A file may contain up to
10 MiB of data, 1,000 records, and 1,000 directory targets. Purview CSV accepts
up to 128 columns and follows the Python CSV reader's per-field size limit.
Malformed or oversized uploads return an error before any results are emitted.

- [Entra sign-in schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0)
- [Entra directory audit schema](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0)
- [Purview audit export](https://learn.microsoft.com/en-us/purview/audit-log-export-records)
- [Management Activity API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema)
