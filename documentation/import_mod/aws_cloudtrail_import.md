# AWS CloudTrail audit logs import

Use **AWS CloudTrail Audit Logs Import** with a local CloudTrail log file, or send the
base64-encoded upload to `POST /query` with the module name `aws_cloudtrail_import`.
The module accepts native CloudTrail JSON with a `Records` array and individual
CloudTrail event JSON, such as the raw record from the console. Gzip archives of
either form are detected by their file signature. It uses the supplied file and
runs offline. CloudTrail Lake query results, Event History `LookupEvents`
wrappers, and CSV exports need to be converted to native event JSON first.

## What MISP receives

Each record becomes an unreviewed `aws-cloudtrail-event` object. The event ID,
operation, service, region, principal, and available AWS request, shared-event,
and addendum IDs are recorded. The original `eventTime` is retained alongside the
UTC datetime, which also marks the point observation on the MISP timeline. An
explicit CloudTrail error or failed `ConsoleLogin` yields a failure. A successful
`ConsoleLogin` yields a success. Other records have an unknown outcome. A valid
source IP is added as `ip-src`. Provider placeholders and service names remain
source text.

Cloud account objects identify the reported principal and recipient accounts.
An explicit IAM role ARN identifies the role. Entries in `resources` with an AWS ARN
link to `cloud-resource` objects. The CloudTrail event region describes the event.
Resource region comes from the resource ARN when present. Every event references a
file object with the source basename, byte count, and SHA-256 of the exact
upload, including its compressed form. The `extracted-from` reference comment gives the
one-based record index in that file. No imported attribute is enabled for IDS
matching or automatic correlation.

Object UUIDs are stable across runs. The event UUID is based on `eventID` and the
source file UUID on its SHA-256. Identical duplicate records in one upload
produce a single event with the earliest source reference. Conflicting records
with the same `eventID` cause an error. Separate records with a `sharedEventID`
remain separate. Import results include record and duplicate counts.

## Source attachment and limits

The default file object carries just source metadata. Enable **Attach the exact
source log** in the file import settings to include the original file as an
attachment. API callers can set `config.include_source` to `true`. The original can
contain sensitive identifiers and request or response data. The default
structured extraction omits `requestParameters`, `responseElements`, raw records,
access-key IDs, and free-text error messages. The computed SHA-256 identifies
the uploaded bytes. AWS log integrity validation using a trail digest is a
separate verification step.

An upload can contain up to 10 MiB of input, 20 MiB of inflated JSON, 1,000 event
records, and 1,000 resource entries across distinct records. Events require a
hyphenated UUID, a timezone-qualified ISO 8601 event time, an event source, and
an event name. Invalid base64, malformed JSON or gzip, exceeded limits, and
invalid records return an error for the upload.

[AWS CloudTrail record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
