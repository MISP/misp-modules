# Atlassian Cloud Audit Logs Import

Import an audit CSV downloaded from Atlassian Administration or saved JSON from the Atlassian Organizations Events API. The module reads the upload locally and requires no Atlassian credentials.

1. In Atlassian Administration, select the organization or site and export its audit log. For API exports, save responses from `/admin/v1/orgs/{orgId}/events` or `/admin/v1/orgs/{orgId}/events-stream`. The importer accepts a response page, a single event or an array of event resources. Follow any reported pagination when collecting the export.
2. In the MISP investigation event, choose **Import from…** → **Atlassian Cloud Audit Logs Import**. Both formats accept UTF-8 with an optional BOM or gzip compression.
3. When the export omits scope, supply the known **Organization ID** and **Site**. The importer takes reported scope from the CSV, Events API organization URL or explicit API containers where available.
4. Enable **Attach the exact source audit export** to store the uploaded bytes in MISP. The source file object's SHA-256 and byte count always describe the exact upload.

The event object exposes the activity or action ID, actor, organization, site, app, authentication, and reported source address when available. API events link to separate affected entities (`context`) and containers such as sites (`container`). Each link records its position in the source array. Account identifiers, email addresses, and IP addresses can correlate. The raw record preserves other reported details, such as changes within an affected entity.

The CSV reader recognizes English headings such as `Activity`, `Date`, `Time`, `Actor`, `App`, `Location` and `IP address`. An explicit offset in a timestamp or a UTC column label establishes the timeline. For local CSV timestamps, supply **Known UTC offset for local CSV times** if it is known for the export. Split an export if the offset changes within its time range and the export omits it. A date without a clock time, an unrecognized format, or a timestamp with unknown offset is retained as text with a warning.

The raw record retains the JSON event or CSV cell values and original headings. To recover a large record, decode its `raw-record-fragment` values as JSON strings and concatenate them in part order. The source file reference records the JSON entry or CSV row location. Saved exports can contain private account, token identifier, and resource details. Set the MISP event distribution to suit that data.

The importer accepts up to 10,000 events, 4,000 affected entities and containers, 10 MiB of upload data, and 20 MiB after gzip expansion. Identical repeats with the same event ID and organization within one upload are included once. An event without a usable ID is identified by its file and position.

[Atlassian audit export](https://support.atlassian.com/security-and-access-policies/docs/export-audit-logs/) · [Atlassian audit log fields](https://support.atlassian.com/security-and-access-policies/docs/view-audit-log-activities/) · [Organizations Events API](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/)
