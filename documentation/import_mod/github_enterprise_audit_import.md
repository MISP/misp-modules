# GitHub Enterprise Audit Logs Import

Import saved GitHub organization or enterprise audit log JSON or CSV, or the separate Git events export when available. The importer processes the uploaded file locally.

1. From the organization or enterprise audit log, export the relevant time range as JSON or CSV. To review Git operations such as clone, fetch, and push, save the separate Git events export when GitHub offers it. Its gzip-compressed JSON Lines file can be uploaded directly.
2. In the investigation event, choose **Import from…** → **GitHub Enterprise Audit Logs Import** and upload a saved export. Plain UTF-8 JSON arrays, individual records, JSON Lines and CSV are supported. The importer also reads these formats wrapped in gzip.
3. For a GitHub Enterprise Server instance or a dedicated GitHub Enterprise Cloud domain, set **GitHub hostname** to the host that produced the export. The default is `github.com`. Enable **Attach the exact source audit export** to retain the original file bytes in MISP.

Each `github-audit-event` links to the source file object through an `extracted-from` reference. The reference identifies the JSON record number, JSON Lines line number or closing line of a CSV row. The file object's SHA-256 and byte count describe the exact upload, including its gzip wrapper.

Events keep the enterprise, organization and repository names and IDs where reported. The importer exposes membership changes, policy settings and GitHub App activity through fields such as actor, affected user, permission, repository visibility and application IDs. It also exposes the reported actor bot flag and user agent as typed attributes. Missing scope values remain absent. GitHub.com usernames, full repository names and application client IDs can correlate, as can reported source IPs and user agents. Correlation on account, repository and application client names or identifiers is disabled for custom hosts to avoid matching unrelated instances.

The timeline uses `created_at` or falls back to `@timestamp`. Both source fields are kept when present. Each raw record is also retained as JSON, with CSV values preserved as strings. For large records, decode each `raw-record-fragment` attribute as a JSON string and concatenate the strings in the order shown in the comments. Audit data can contain private account, repository and request details. Set the investigation event's distribution to suit that data.

The importer handles up to 10 MiB per upload, 20 MiB decompressed, 1,000 records, and 256 KiB of serialized JSON per record. A record with a native `_document_id` has a stable identity within its GitHub host. Identical repeats within a file are included once, and conflicting records with the same ID produce an error. Records without a usable ID use the source file and record position so repeated entries keep their provenance.

GitHub documents that its separate Git export omits Git operations initiated directly through its browser UI or APIs. That export alone cannot establish that no action occurred.

[GitHub Enterprise audit exports](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/exporting-audit-log-activity-for-your-enterprise)
