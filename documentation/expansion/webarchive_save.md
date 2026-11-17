# Webarchive Save Page Now

`webarchive_save` **submits a URL for archiving** using Internet Archive's
Save Page Now API. The existing `webarchive` module looks up existing snapshots;
this module sends one `POST https://web.archive.org/save` per invocation.

Configure Internet Archive S3 `access_key` and `secret_key` from
https://archive.org/account/s3.php on the module server. These are S3 API keys,
not your account password. They are sent in the `Authorization: LOW` header
only to the fixed HTTPS Internet Archive endpoint. No new dependencies are
needed beyond requests and PyMISP.

```json
{
  "module": "webarchive_save",
  "attribute": {
    "type": "url",
    "value": "https://example.org/report",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
  },
  "config": {
    "access_key": "YOUR_ACCESS_KEY",
    "secret_key": "YOUR_SECRET_KEY",
    "poll_attempts": "3"
  }
}
```

Inputs are `url` or `link` attributes with valid UUIDs. HTTP(S) URLs are required;
embedded credentials, whitespace, backslashes and invalid ports are rejected.
Fragments are removed before submission; the original attribute is preserved.
Invoking the module sends the URL, including its query string, to Internet
Archive for public archiving. It may cause Internet Archive to fetch the page
and its resources. Use this submission module only for URLs intended for that
disclosure. It does not run as a hover module.

| Configuration | Default | Meaning |
| --- | --- | --- |
| `access_key`, `secret_key` | required | Internet Archive S3 API credentials. |
| `timeout` | 30 | Integer 1–120 seconds shared by submission, polling and polling delays. Requests use the remaining budget, with connection time capped at 10 seconds. |
| `poll_attempts` | 0 | Integer 0–6. Zero returns the accepted job immediately; otherwise query only this submitted job, with two seconds between polls. |

The response uses `misp_standard` and preserves the original attribute. An
`annotation` object references it and contains a JSON receipt with provider,
submitted URL, submission time, `job_id`, `status_url` and status:

- `submitted`: the API accepted a job; completion has not been checked.
- `pending`: the job is still queued or running after the bounded polling.
- `success`: the API reports completion with a valid capture timestamp.
- `error`: the API reports job failure.

Only API-reported success produces a `page-capture` object with the captured
URL, Wayback link and UTC capture date. This reuses the standard template
already bundled for `webarchive`; no new template is needed. Snapshot playback
is not independently verified, and Internet Archive may take time to expose it.
All generated attributes use `to_ids=false`; receipt correlation is disabled.

If polling fails, the accepted job ID and status link are retained with
`poll_error`, allowing follow-up against the job status endpoint without a new
submission. This status endpoint requires API authentication; it is not a
snapshot link. A pending job is never represented as a completed capture.

The module never retries submission automatically. A transport timeout or an
invalid acknowledgement may occur after the service accepted the job: the
module reports an unconfirmed outcome rather than claiming rejection. Repeated
invocations submit new jobs and may create duplicates. HTTP errors, including
rate limits and authentication failures, are reported without following
redirects or forwarding credentials. Responses are limited to 1 MiB per call.
Polling is bounded by `poll_attempts` and a shared monotonic deadline. The
budget is also capped at one second below the query's top-level `timeout`
(300 seconds by default), leaving time to return the receipt. If there is not
enough time for another polling delay, the module stops and returns the accepted
job with `poll_error`. Transport timeouts use the remaining budget; the deadline
is also checked between streamed response chunks. As with requests' normal
timeouts, a socket read already in progress cannot be interrupted by the
between-chunk check. No further polls are scheduled after budget exhaustion.

This initial provider is Internet Archive. It does not submit to archive.today
or bypass another provider's interactive controls. The submission/authentication
contract follows Internet Archive's own
[Open Library client](https://github.com/internetarchive/openlibrary/blob/master/openlibrary/core/ia.py).
