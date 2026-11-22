# Kubernetes API Audit Logs Import

The importer reads saved Kubernetes API server audit logs locally. It works with files supplied by the analyst.

| Source | Supported input |
| --- | --- |
| Kubernetes | Native `audit.k8s.io/v1` JSON Lines, an individual `Event`, a JSON array of events, or an `EventList`. |
| Amazon EKS | Saved CloudWatch Logs `FilterLogEvents` or `GetLogEvents` JSON, a decoded CloudWatch subscription with `logEvents`, or a Lambda subscription envelope with base64-encoded gzip at `awslogs.data`. |
| Azure AKS | Azure Monitor diagnostic `records` with category `kube-audit` or `kube-audit-admin`, AzureDiagnostics rows with `log_s`, or `AKSAudit` or `AKSAuditAdmin` Log Analytics rows. Log Analytics API responses with `tables`, `columns` and `rows` are also supported. |

In the investigation event, choose **Import from…** → **Kubernetes API Audit Logs Import** and upload a UTF-8 JSON or gzip file. Import all saved CloudWatch pages when the API reports a continuation token. To compare stages split across native files or CloudWatch exports that omit cluster scope, supply the same **Cluster identifier** on each upload. Use an identifier that distinguishes clusters across accounts and regions. For events with neither a reported cluster nor an operator-supplied identifier, the upload's SHA-256 scopes the request.

The importer creates one `kubernetes-audit-request` per cluster scope and `auditID`. Reported Azure resource IDs and CloudWatch log groups, with account where available, supply the scope when present. Each request links to the original file and its `kubernetes-audit-stage` objects. The request shows the earliest reported request time and the latest reported stage time and summarizes the context from the stage with the most recorded request fields.

Each stage retains its reported timestamp, authenticated and impersonated principals, verb, request URI, API object reference, response status and authorization decision when present. Stage references follow reported timestamps, with Kubernetes stage order used for ties and for stages without timestamps. Distinct observations of the same stage are kept. Identical events within the same cluster and upload are included once. Audit policies can omit stages, and `ResponseStarted` typically applies to long-running requests. Source IPs and user agent are reported claims. Kubernetes warns that clients can supply some entries in the IP chain.

Every stage links to its position in the source file. The file object's SHA-256 and byte count describe the exact upload. Enable **Attach the exact source audit export** to store the file, including request and response bodies. Audit exports can include sensitive data such as credentials, usernames and private resource details. Set the investigation event's distribution to suit that data.

The importer accepts files up to 10 MiB, up to 20 MiB of decompressed input and up to 2,000 distinct stages across 4,000 rows. CloudWatch subscription payloads in the file can decompress to up to 20 MiB in total.

[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Amazon EKS control plane logs](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) · [Azure AKS monitoring reference](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference)
