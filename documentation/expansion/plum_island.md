# Plum Island IP History

`plum_island` reads historical IPv4/IPv6 observations using
`POST /api/v1/discovery/show_ip`. It returns referenced MISP annotation objects
with raw scan documents, document UIDs, `first_seen`/`last_seen`, UID tags and
missing-document warnings. A summary retains available requested hostnames,
the selected hostname group, date scope, total and returned observation counts,
and whether the result is complete. UID tags describe a whole scan document;
they are not applied as MISP tags to the IP or individual services.

Requires **Discovery API v1**, added to Plum Island `main` after v0.2610.0.
Release v0.2610.0 alone does not expose this API. See the
[upstream contract](https://github.com/D4-project/Plum-Island/blob/main/documentation/discovery.md).
Install the updated controller and synchronize roles using its
`tools/initial_setup.py --roles-only`. The account needs `can_show_ip` on
`DiscoveryApi`; Plum's bundled Read Only role includes it.

## Configuration

| Setting | Meaning |
| --- | --- |
| `url` | Required HTTPS controller base URL, e.g. `https://plum.example.org`. Include a deployment prefix if applicable; omit `/api/v1/discovery`. |
| `username`, `password` | Dedicated Plum FAB account. Login uses `provider: db`; these are not scanner `AGENT_KEY` credentials. |
| `access_token` | Alternatively, a FAB JWT. Takes precedence over initial login. If account credentials are also provided, they renew authentication once after HTTP 401. |
| `hostname` | Optional requested-hostname group. Empty selects **IP-only scans**, not all hostname groups. The summary lists available groups even when the selected group has no observations. |
| `max_results` | Maximum returned observations in total: 25 by default, 1–100. |
| `max_pages` | Maximum Discovery requests: 10 by default, 1–20. |
| `from_ts`, `to_ts` | Optional nonnegative UTC epoch seconds. Supplied dates use the controller's inclusive interval-overlap rules and whole-day normalization; without dates the selected group's full history is eligible. |

Configure `url` and either account credentials or `access_token`. Requests verify
TLS, reject redirects, and use connection/read timeouts of 5/30 seconds. Only
HTTP 401 with configured account credentials causes one authentication renewal
and retry. Errors include an actionable HTTP status without echoing server
response bodies or credentials. A 404 remains an error because it can indicate
an absent Discovery API, an unknown IP or an unknown hostname group.

Install the updated misp-modules package and restart its service. Enable
`Plugin.Enrichment_services_enable` and `Plugin.Enrichment_plum_island_enabled`
in MISP, then configure the module's settings. The module identifier is
`plum_island`; the display name is **Plum Island IP History**. It accepts an
`ip-src` or `ip-dst` attribute containing one IP address, not a CIDR.

Example `/query` request (replace the token locally):

```json
{
  "module": "plum_island",
  "attribute": {
    "type": "ip-dst",
    "value": "192.0.2.1",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "url": "https://plum.example.org",
    "access_token": "YOUR_FAB_JWT",
    "hostname": "www.example.org",
    "max_results": "25"
  }
}
```

All new evidence has `to_ids=False`; annotation text also disables correlation.
The original attribute and its metadata are preserved, and annotations reference
its UUID. Scan text remains untrusted evidence. The module does not schedule
scans, resolve DNS or call WHOIS/PDNS services. Historical observations do not
prove current exposure. `complete: false` explicitly indicates that the result
or page budget stopped pagination; narrow the date range or raise the budget
within its documented bounds. Completeness refers to the selected group and
date scope, not to all possible hostnames or all Plum data.

Use [Plum Island Search](plum_island_search.md) for domain, network and certificate pivots.
