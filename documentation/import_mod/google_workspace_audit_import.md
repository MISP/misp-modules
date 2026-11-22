# Google Workspace Audit Logs Import

Import saved Google Workspace Admin SDK Reports API `activities.list` responses for `login`, `admin`, `drive`, and `token` (OAuth). The importer reads the uploaded file locally and requires no Google credentials.

1. Save the JSON responses for the relevant customer, time window and applications. Follow each response's `nextPageToken` when collecting the export.
2. In the investigation event, select **Import from…** → **Google Workspace Audit Logs Import** and upload a saved response. A single `Activity` or a JSON array of `Activity` records is also accepted. An array can combine the four applications. UTF-8 JSON and gzip are supported.
3. Enable **Attach the exact source audit log** if you want the original response stored in MISP. The source file object's SHA-256 and byte count always refer to the bytes as uploaded, including any gzip wrapper.

The import creates a `google-workspace-audit-activity` for each compound Reports API ID. Its attributes retain the customer, application, timestamp as reported, and unique qualifier. A normalized UTC timestamp is also available for the timeline. Each nested `events[]` entry becomes a `google-workspace-audit-event` with its original position and a `contains` reference from the parent activity. Repeated event names retain their individual ordinals and parameters. Each activity points to the source file through an `extracted-from` reference.

Use the reported actor email, profile ID and source IP to find related activities. Within one upload, activities that share a usable actor profile ID or email within the same customer receive `related-to` links. MISP can correlate those values and email addresses in affected-user, affected-group, document-owner and sharing-target fields with other imports. The event objects expose selected fields for sign-in and MFA, affected users and admin roles, Drive file IDs and sharing, and OAuth client IDs and scopes. A matching value identifies a shared value in two records and is a starting point for checking the sequence of activity.

The importer preserves each `parameters[]` and `sensitiveParameters[]` entry as JSON with its source position. It keeps repeated and nested values, including false booleans and zero. Raw parameter attributes have correlation and IDS flags disabled. Audit responses and attachments may contain sensitive account, resource, or parameter values. Set the investigation event's distribution to suit that data.

If the saved response still reports a next page, collect and import the remaining responses. The module handles up to 10 MiB per upload, 20 MiB of decompressed JSON, 1,000 activities, and 2,000 nested events. A parameter can occupy up to 32 KiB as serialized JSON. The importer also limits the number of attributes to 1,000 per nested event and 12,000 across all activities and events in an upload. Identical copies of an activity within an upload are included once. An import fails with an error if two records share the same compound ID and differ in content.

[Google Workspace Reports API activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)
