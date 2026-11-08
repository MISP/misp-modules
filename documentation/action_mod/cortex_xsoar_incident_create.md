# Cortex XSOAR Incident Create

`cortex_xsoar_incident_create` creates a Cortex XSOAR 8 incident referencing one
selected MISP event using `POST /xsoar/public/v1/incident`. It sends the source
UUID, selected-data counts and provenance labels. It does not export the full
event or request updates to an existing incident.

## Server configuration

Set these environment variables on the **misp-modules server**, then restart its
process:

| Variable | Meaning |
| --- | --- |
| `CORTEX_XSOAR_URL` | HTTPS API origin copied from XSOAR's API Keys page. A full root ending in `/xsoar/public/v1` is also accepted. Use the API FQDN, not the browser/UI FQDN. |
| `CORTEX_XSOAR_API_KEY` | XSOAR API key permitted to create incidents in the intended tenant. |
| `CORTEX_XSOAR_API_KEY_ID` | Required positive numeric API key ID. |
| `CORTEX_XSOAR_AUTH_TYPE` | `advanced` (default) or `standard`, matching the generated key. |
| `CORTEX_XSOAR_TIMEOUT` | Timeout in seconds, 1–120; default 20. |
| `CORTEX_XSOAR_MISP_URL` | Optional HTTPS MISP base URL, including a deployment subpath. No credentials, query or fragment. |

Connection settings cannot be overridden by workflow parameters or query `config`.
Standard keys send the raw key in `Authorization`, without a Bearer prefix.
Advanced keys send `SHA256(key + nonce + timestamp)`, plus fresh nonce/timestamp
headers. Both send `x-xdr-auth-id`. Authentication is explicit, preventing
`.netrc` substitution. These are XSOAR credentials and routes, rather than XDR
IOC API settings or legacy XSOAR 6 authentication.

HTTPS verification, requests proxy settings and `REQUESTS_CA_BUNDLE` are
preserved. Redirects and automatic retries are disabled. API replies are limited
to 2 MiB. Keys and backend error bodies are never returned.

## Workflow parameters

| Parameter | Meaning |
| --- | --- |
| `incident_type` | Existing XSOAR incident type; default `Unclassified`, as in the official API example. Up to 128 UTF-8 characters without controls or surrounding whitespace. |
| `name_prefix` | Default `MISP event`; 1–64 ASCII letters, digits, spaces, `.`, `_` or `-`. The event UUID is appended. |
| `severity` | Finite numeric XSOAR severity from 0 to 4, including fractional values; default 2. Sent as a JSON number. |
| `create_investigation` | Default false. Set true to request investigation creation and the appropriate playbook for the incident type. |
| `dry_run` | Default true. Set explicitly to false to request a new incident. Missing, null and empty values preview. |

Dry run is enabled by default and needs no API credentials or network access.
Investigation/playbook creation requires an explicit opt-in. If a source MISP
URL is configured, it is validated during previews too.

Supply exactly one non-deleted event with a valid, non-empty UUID. Bare events,
`{"Event": {...}}`, a one-element list and legacy core-format envelopes with
selected `Attribute`/`Object` collections beside `Event` are supported. Multiple
events and workflow filters are rejected. `filteredItems` and `matchingData` are
rejected by key presence, including null/empty values, to prevent fallback to a
broader event. Put the explicit selection in `data`.

Example `/query` request:

```json
{
  "module": "cortex_xsoar_incident_create",
  "params": {
    "incident_type": "Unclassified",
    "severity": "2",
    "create_investigation": "false",
    "dry_run": "true"
  },
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [
        {"type": "domain", "value": "example.org", "to_ids": true}
      ]
    }
  }
}
```

## Payload and provenance

The allowlisted API payload contains `name`, `type`, `severity`, `details`,
`labels` and explicit `createInvestigation`. It never copies an incoming `id`,
`version`, status, playbook ID or raw JSON into the create/update endpoint.

Details contain the source UUID and counts of active selected attributes,
objects and IDS attributes. Deleted objects/attributes are excluded, and missing
`to_ids` means false. Active attachments count as attributes, but their data is
not copied. Event titles, observable values, comments, tags and binary content
are not transferred. Counts describe the selection, not necessarily the complete
source event.

Labels include `misp_source: misp-modules` and `misp_event_uuid: <uuid>`. If
configured, the source URL is added to details and a `misp_event_url` label using
`<MISP base>/events/view/<uuid>`. Preserve the source-event label in tenant
preprocessing rules so the module can verify incident provenance.

## Response handling

The result uses `result_key: cortex_xsoar_incident_create`. Preview returns
status `planned` and the exact API payload. A live invocation submits one POST.
The current XSOAR 8 OpenAPI contract distinguishes:

| HTTP response | Module behavior |
| --- | --- |
| **201** | Validate the flat incident object, string ID and source-event label, then report `created`. |
| **200** | The request was processed **without creating an incident**, for example because of a preprocessing rule. Return an error with `success: false`, status `not_created`, and no incident ID. Empty/non-JSON bodies are permitted for this documented outcome. |
| Other status, timeout or malformed/unconfirmed 201 | Return an error and status `uncertain`; inspect XSOAR before retrying. |

These status meanings come from the [XSOAR 8 incident endpoint's current
OpenAPI responses](https://cortex-docs.paloaltonetworks.com/xsoar-8-api/cortex-xsoar-8.x-apis/incidents).
The older Demisto `POST /incident` specification describes HTTP 200 with an
`IncidentWrapper` as creation. That is a different API contract: this module
targets XSOAR 8's `/xsoar/public/v1/incident` and does not support the legacy
endpoint. Treating 200 as creation here would incorrectly report a suppressed
incident as created. Existing client and action tests cover both a flat 201
creation response and a 200 outcome with empty, non-JSON or ID-bearing bodies.

Despite its schema name `IncidentWrapper`, the 201 response is a **flat** object,
rather than `{"incident": {...}}`. Created results include the actual returned
name, incident type and severity. Tenant mappings can change these fields; when
they do, the module reports creation with a warning and the actual values.
An optional returned investigation ID is included, but investigation/playbook
completion is not polled or asserted. Arbitrary incident fields are not copied.

Local input/configuration errors cause no API call. Live connection configuration
errors report `not_attempted`. A 200 outcome is explicitly `not_created`, rather
than falsely claiming creation or an uncertain 201 acknowledgement.

Each live invocation requests a new incident. No native idempotency guarantee is
documented, and the module does not search for duplicates or update existing
incidents by ID. Tenant preprocessing/deduplication rules still apply. Inspect
the tenant for the source UUID before retrying an uncertain write; an incident
and possibly an investigation may already exist. There are no automatic retries.

## References

- [Supplied XSOAR 8 SaaS API guide](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/troubleshoot-and-reference/reference/cortex-xsoar-api)
- [Authentication examples](https://cortex-docs.paloaltonetworks.com/xsoar-8-api/make-your-first-api-call)
- [Current incident API schemas and response codes](https://cortex-docs.paloaltonetworks.com/xsoar-8-api/cortex-xsoar-8.x-apis/incidents)
