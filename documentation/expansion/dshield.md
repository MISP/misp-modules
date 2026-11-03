# DShield / SANS Internet Storm Center

Expand `ip-src` or `ip-dst` attributes with the public ISC IP summary API.
No API key is required. Both public IPv4 and IPv6 addresses are accepted.
Multicast, reserved and IPv4-mapped IPv6 inputs are rejected before network access.

| Setting | Purpose |
| --- | --- |
| `user_agent` | Identify the deployment, preferably including a contact email, as requested by ISC. Defaults to the module name and MISP project URL. |

The module returns the original attribute, an annotation referencing its UUID,
an ASN object when available, and an ASN abuse-contact email when available.
The annotation retains packet-report counts, unique target counts, first/last
seen dates, update time and individual threat-feed observations.
Counts describe reports collected by ISC; zero reports do not establish safety.
New attributes have `to_ids=false`. The original attribute keeps its metadata.

HTTP 429 is returned without retries. Wait at least five minutes and honor the
service's `Retry-After` header before another lookup. A 404/204 is labelled as
no information. Network failures, malformed responses and mismatched IPs are errors.

Enable `dshield` in MISP's enrichment settings after restarting misp-modules.
No shared helper or new Python package is required beyond existing `requests` and PyMISP.

Validate offline with `python -m pytest tests/test_dshield.py`.

[ISC API documentation](https://www.dshield.org/api/#ip)
