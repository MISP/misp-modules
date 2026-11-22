# Azure Activity Log Import

Select **Azure Activity Log Import** (`azure_activity_log_import`) in MISP's
file import interface. The importer reads saved UTF-8 JSON, with optional
gzip compression, and processes the upload locally.

| Source | Accepted input |
| --- | --- |
| Azure CLI and Resource Manager REST | A single event, a JSON array from `az monitor activity-log list`, or a saved REST response with `value[]`. [Activity Logs List](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01) |
| Azure Monitor diagnostic settings | Activity Log records or a JSON payload with `records[]`, such as a Storage or Event Hubs export. [Activity Log export schema](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema) |
| Azure Monitor Log Analytics | Named-column `AzureActivity` JSON records or a saved Logs query API response with one `AzureActivity` result table. [AzureActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) |

Save an Azure CLI export for a specific subscription and time window.

```sh
az monitor activity-log list --subscription SUBSCRIPTION_ID \
  --start-time 2026-11-21T00:00:00Z --end-time 2026-11-22T00:00:00Z \
  --max-events 1000 --output json > azure-activity.json
```

The REST importer reports when a response includes a next page. Import
additional saved pages separately.

## Imported evidence

- Each `azure-activity-log-event` records the reported operation, result
  and substatus or diagnostic signature, correlation ID, and available
  subscription and resource identifiers. It preserves the original
  timestamps alongside UTC timeline values at microsecond precision. The
  importer reports records that omit event time. A projected CLI export can
  supply the operation through `authorization.action`, which the importer
  records as the field's source.
- Diagnostic exports can use a category such as `Write`. The importer retains
  that source category and projects the Activity Log category from
  `properties.eventCategory` or the schema's Administrative default.
- Caller values come from the event or from a reported identity claim with
  its source path. Caller object, application, and directory tenant identifiers
  use separate attributes. The Log Analytics `TenantId` column populates
  the workspace ID.
- For role assignment changes, available target principal, role definition,
  assignment ID, and scope come from one reported request or response body.
  Actor authorization evidence has its own fields. The source distinguishes
  a requested target from a response and retains the reported operation
  result. [Azure RBAC activity log examples](https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report)

Each event links to a source `file` object by its position in the upload.
The file SHA-256 identifies the exact uploaded bytes. The original export
can be attached with **Attach the exact source audit log**. The projection
selects audit fields and role assignment details. Full request bodies,
response bodies, and unselected claims are available via the optional
original attachment. All attributes have IDS and correlation disabled.

Events with a native event ID use the identifier and source schema as their
stable identity. Resource Manager record IDs provide a fallback when
`eventDataId` is absent. Identical repeats count once within the upload.
Conflicting entries with the same identity fail the upload. Records without
an event identifier retain their individual positions.

An upload accepts up to 10 MiB of input, 20 MiB after decompression, and
1,000 events. Log Analytics result tables accept up to 128 columns. Install
the companion `azure-activity-log-event` template on the MISP server.

## Module API

```json
{
  "module": "azure_activity_log_import",
  "filename": "azure-activity.json.gz",
  "data": "<base64 file>",
  "config": {"include_source": false}
}
```
