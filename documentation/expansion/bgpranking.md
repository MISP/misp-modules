# BGP Ranking

Enrich an `AS` attribute with the public [CIRCL BGP Ranking](https://bgpranking.circl.lu/)
service. No API key or additional dependency is required beyond `requests` and
PyMISP. Both `AS13335` and `13335` are accepted, including lowercase `as` prefixes.

| Setting | Default | Meaning |
| --- | --- | --- |
| `date` | Yesterday in UTC | Exact day to query, in `YYYY-MM-DD` format |
| `address_family` | `v4` | `v4` or `v6`; sent to the API as `ipversion` |

The module sends one HTTPS `POST` to `/json/asn`, with a 30-second timeout and
redirects disabled. It requests an explicit date: the service echoes the query
in `meta` and does not fall back to the latest available ranking. An empty daily
dataset therefore produces no ranking object. HTTP errors, API errors, timeouts
and malformed responses return a module error without partial results.

Results preserve the source attribute and its UUID and metadata. An `asn` object
references it using `describes`; when a ranking entry exists, that object also
references a `bgp-ranking` object using `ranked-with`. These are existing standard
MISP templates; no template installation or update is needed. Generated
attributes have `to_ids=false`.

The ranking object records the score, position, query date at midnight UTC, and
address family. Position 1 is the most malicious ASN of the day, with the highest
score. The number of known ASNs is kept in the object comment. Comparisons need
the same date and address family; this is ASN context, not a verdict on every
IP address hosted by that ASN.

The service returns a score of zero and a `null` position when an ASN has no
ranking entry. The module returns ASN context only and explains that absence in
the object comment. This also covers days or address families with no dataset;
absence is not a clean verdict. Missing descriptions do not discard rankings.
Descriptions are split at the last comma only when the suffix is a two-letter
uppercase country code, preserving commas within organisation names. The API
returns its latest ASN description, even for historical ranking queries.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "bgpranking",
  "attribute": {
    "type": "AS",
    "value": "AS13335",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "date": "2026-11-10",
    "address_family": "v4"
  }
}
```

The module was removed in the 2024 dependency migration. This restores the
`bgpranking` expansion and hover module against the current API without the old
`pybgpranking` client dependency.

Validation: `pytest tests/test_bgpranking.py` uses captured public API responses
and mocked failures; it requires no network access. The fixtures were captured
from the CIRCL service on 2026-11-11 for the 2026-11-10 ranking date.

References:

- [API documentation](https://bgpranking.circl.lu/doc/)
- [Service implementation](https://github.com/D4-project/BGP-Ranking/blob/main/website/web/genericapi.py)
- [Ranking semantics](https://github.com/D4-project/BGP-Ranking/blob/main/bgpranking/bgpranking.py)
- [Existing bgp-ranking template](https://github.com/MISP/misp-objects/blob/main/objects/bgp-ranking/definition.json)
