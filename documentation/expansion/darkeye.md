# DarkEye

Look up a domain or hostname in [DarkEye](https://darkeye.io/), using
[HaveIBeenRansom](https://haveibeenransom.com/) and
[Breach House](https://breach.house/). Configure a key for either product or both.
Each configured product receives the target domain. This is an external expansion
module; it does not run automatically on hover.

The result is one `text` attribute with `to_ids=false`. Its JSON value contains
the domain, products that completed, records, count, errors and truncation status.
Every record identifies its product and category. The report keeps only listing
metadata: id, title, website, group, country and discovery date. Text fields are
capped at 512 characters and dates at 10 characters. It does not retain leaked
records, credentials, proof files, descriptions or leak-site links.

A listing does not establish that a domain is malicious or that an incident is
confirmed. No match does not establish that the domain is safe. The module adds
no verdict tags or related domain indicators.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `haveibeenransom_api_key` | none | Optional HaveIBeenRansom API key |
| `breachhouse_api_key` | none | Optional Breach House API key |
| `max_pages` | `5` | HaveIBeenRansom page cap, from 1 to 20 |
| `max_records` | `100` | Records retained per product, from 1 to 500 |
| `limit` | `25` | Breach House results requested per source, from 1 to 200 |
| `timeout` | `30` | Request timeout in seconds, from 1 to 120 |

At least one API key is required. These are module bounds, not plan allowances.
The default request budget is at most five HaveIBeenRansom calls and one Breach
House call. There are no automatic retries. A record cap can stop pagination
earlier. Keys are sent in bearer headers. Redirects are rejected, sessions are
separate for each product, and ambient proxy and `.netrc` settings are disabled.

HaveIBeenRansom uses the domain metadata endpoint for ransomware and breach
listings. This module does not request full leaked data or full stealer records.
Breach House uses its cross-source search for ransomware, breach, lead and stealer
listings. Its free-text hits are retained only when the website matches the target
domain or a subdomain. If there is no website, the title must mention the domain
as a complete hostname.

## Errors and limits

If one product fails, the module retains the other product's completed result
and reports the failure in `errors`. If a later HaveIBeenRansom page fails, the
module discards records from that incomplete lookup. If every configured product
fails, the module returns an error instead of an empty report. Malformed responses are
errors as well.

`status` is `partial` when there are errors or a retrieval limit was reached;
otherwise it is `complete`. `truncated` describes retrieval limits. Breach House
results can be truncated before domain filtering, so a partial report may contain
no matching records. A complete empty report means only that the configured
products returned no matching listings.

## Verification

`tests/test_darkeye.py` exercises the handler with synthetic HTTP responses and
validates the returned attributes with PyMISP. It covers independent keys,
partial and total failures, pagination, deduplication, limits, hostname matching,
malformed responses, metadata filtering and credential isolation. No live API
queries or MISP UI tests were performed for this contribution.

API references: [HaveIBeenRansom](https://haveibeenransom.com/howapi) and
[Breach House](https://breach.house/docs).
