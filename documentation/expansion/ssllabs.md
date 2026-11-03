# Qualys SSL Labs API v4

Expand public `domain` and `hostname` attributes with TLS assessments.

| Setting | Purpose |
| --- | --- |
| `email` | Required organization email already registered with SSL Labs API v4. |
| `allow_scan` | Defaults to `false`: no API request is made. Set `true` to permit assessments before calling SSL Labs. |
| `max_age` | Preferred maximum cached report age, in hours (1–720); defaults to 24. A cache miss can start an assessment. |

Register with Qualys separately, following its API reference. The module does
not register users. Assessments run on Qualys servers and may take minutes;
check the service terms before using it.

The `analyze` endpoint can start a new scan even with `fromCache=on`, so the
module requires `allow_scan=true` before making any API request. There is no
cache-only mode. With consent enabled, each invocation makes one request and
prefers cached reports using `fromCache=on` and `maxAge`. DNS/IN_PROGRESS
responses return a progress annotation: invoke the module again later to
retrieve results. It never sends `startNew`, so it does not force a restart.
Requests set `publish=off`. Reports are not placed on the public results board.

READY reports produce referenced assessment annotations, an `ip-port` object
per endpoint and `x509` certificate objects with fingerprints and validity dates.
Grades, protocol/cipher details and weakness-test results are included only
for endpoints whose assessment completed successfully. Failed endpoints retain
their status without importing a misleading grade. Numeric test results are
kept as context, including unknown and error values.

Source metadata is preserved, and new enrichment has `to_ids=false`.
An assessment ERROR is returned as a module error.
There is no polling loop or automatic retry inside a module request.

Enable `ssllabs` in MISP's enrichment settings after restarting misp-modules.
Validate offline with `python -m pytest tests/test_ssllabs.py`.

[API v4 reference](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md)
