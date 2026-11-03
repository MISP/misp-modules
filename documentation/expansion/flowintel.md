# Flowintel case lookup

The `flowintel` enrichment/hover module queries an existing Flowintel instance for
cases containing the selected MISP attribute value. Hits return `link` attributes
to `<Flowintel root>/case/<id>` with the case titles in their comments and
`to_ids=false`. No match returns an empty attribute list; connection, API and
authentication failures return errors.

## Requirements and configuration

Install this version of misp-modules in the service's Python environment and
restart the service. Flowintel must provide `POST /api/case/search/attribute`;
the case-title search API alone does not support this lookup.

In MISP's **Administration → Server Settings & Maintenance → Plugin settings**,
enable the enrichment service and `Plugin.Enrichment_flowintel_enabled`. Set:

| Module setting | Description |
| --- | --- |
| `url` | Required Flowintel application root, e.g. `https://flowintel.example.org`. Include any deployment subpath and omit `/api`. |
| `apikey` | Required Flowintel API key. A read-only user is sufficient. |
| `verify_ssl` | Certificate verification: `true` by default; set `false` only when explicitly required for your deployment. |
| `timeout` | Positive request timeout in seconds, default `30`. |

These fields appear as `Plugin.Enrichment_flowintel_<setting>` in MISP.
Select **Flowintel case lookup** when enriching a supported attribute.

## Matching and permissions

The module sends only the selected attribute value using `X-API-KEY`
authentication. Flowintel searches standalone attributes and attributes within
MISP objects using exact equality under its database collation, across attribute
types. Open and completed cases are included and each case appears once.
Composite values are searched verbatim; the module does not search individual
components, case titles, notes, or descriptions.

Flowintel filters the results using the API user's usual case permissions.
Choose that user to match the cases you want MISP users to discover: matching
case titles and links are returned using that account's visibility. Opening a
link requires a Flowintel login with access to the case.

An HTTP 404 means the API endpoint or configured application root is missing;
it is not treated as an empty match.
