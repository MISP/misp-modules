# Pulsedive indicator lookup

Expand `ip-src`, `ip-dst`, `domain`, `hostname` or HTTP(S) `url` attributes using
Pulsedive's existing indicator database. The module never submits an indicator
or starts an active scan.

| Setting | Purpose |
| --- | --- |
| `api_key` | Optional Pulsedive API key. Keyless requests have stricter service limits. |

Pulsedive's documented API sends the key in a query parameter. Avoid enabling
HTTP debugging or URL logging when using a key. Module errors omit request
URLs and remote error bodies.

The original attribute and its metadata are preserved. A referenced annotation
retains risk, retirement state, risk factors, timestamps, linked threats and
feed provenance. Observed DNS A/AAAA records produce a `domain-ip` object for
domain queries. DNS names, reverse-DNS PTR names for IP queries and redirect
indicators become typed pivot attributes.
Historical property lists are flattened and DNS addresses deduplicated.
Leading/trailing API key whitespace is removed; a blank key uses keyless lookup.
All new enrichment has `to_ids=false`; risk does not automatically mark the
source attribute as malicious. A 404/204 is labelled as no information.

Enable `pulsedive` in MISP's enrichment settings after restarting misp-modules.
The module uses existing `requests` and PyMISP dependencies.

Validate offline with `python -m pytest tests/test_pulsedive.py`.

[Indicator API](https://docs.pulsedive.com/api/indicator/get-by-value)
