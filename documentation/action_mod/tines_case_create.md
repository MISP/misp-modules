# Tines Case Create

`tines_case_create` creates one Tines case referencing one selected MISP event.
It uses the current [`POST /api/v2/cases`](https://www.tines.com/stories/docs/api/cases/create/)
API. The older Cases v1 create API is deprecated and scheduled for removal on
December 1, 2026.

## Server configuration

Configure these environment variables on the **misp-modules server**, then
restart its process:

| Variable | Meaning |
| --- | --- |
| `TINES_URL` | HTTPS tenant origin, for example `https://example.tines.com`. Custom/self-hosted origins are supported; omit paths. |
| `TINES_API_KEY` | Tines API key authorized to create cases in the selected team. Sent in `X-User-Token`. |
| `TINES_MISP_URL` | Optional HTTPS base URL of the source MISP, including any deployment subpath. Produces `misp_event_url` metadata. |

Workflow parameters and query `config` cannot override these connection settings.
Use a suitably scoped API key and protect access to the module server. HTTPS
certificate validation, requests proxy settings and `REQUESTS_CA_BUNDLE` are
preserved. Requests have a 20-second timeout and 2 MiB response limit. Redirects
and automatic retries are disabled. Keys and remote error bodies are not returned.
HTTP 404 may mean that the key lacks access, rather than that a resource is absent.

Dry runs require no API credentials and perform no network requests. If
`TINES_MISP_URL` is configured, it is validated for both preview and creation.

## Workflow parameters

| Parameter | Meaning |
| --- | --- |
| `team_id` | Required positive numeric Tines team ID. |
| `name_prefix` | Default `MISP event`; 1–64 ASCII letters, digits, spaces, `.`, `_` or `-`. The event UUID is appended. |
| `priority` | `info`, `low`, `medium`, `high` or `critical`, case insensitive; default `medium`. |
| `dry_run` | Default `true`. Set explicitly to `false` to create a new case. Missing, null or empty values preview. |

Use the action on a workflow that supplies exactly one selected MISP event. Bare
events, `{"Event": {...}}`, a one-element list of these, and legacy core-format
envelopes with selected `Attribute`/`Object` collections beside `Event` are
supported. The event must have a valid UUID and must not be deleted. Multiple
events and workflow filters are rejected before any API call.

Example `/query` request (preview):

```json
{
  "module": "tines_case_create",
  "params": {
    "team_id": "7",
    "priority": "medium",
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

## Created case and results

The new case is explicitly `OPEN`, with the configured priority and a name formed
from the prefix and event UUID. The description contains the UUID and counts of
active selected attributes, objects and IDS attributes. Metadata includes:

- `misp_source`: `misp-modules`;
- `misp_event_uuid`;
- `misp_attribute_count`, `misp_object_count`, `misp_ids_attribute_count`;
- optional `misp_event_url`: the configured MISP base plus `/events/view/<uuid>`.

Counts describe only the workflow selection, including attributes inside active
objects. Deleted attributes and deleted objects are excluded. Missing `to_ids`
means false. Observable values, event title, comments, tags, user mentions and
binary attachments are not copied. This creates a case reference, rather than a
complete event export or ongoing synchronization. Tines applies its normal author
and assignee defaults for the API token; the module does not request a template,
assignees, tags or custom case fields.

The workflow result uses `result_key: tines_case_create`. Preview returns
`data.status: planned` with the exact API payload. Creation requires HTTP 201 and
checks the case ID, target team, name, source metadata, status and priority before
returning `data.status: created`, the case ID and a link constructed from the
configured tenant origin. Provider-supplied URLs are not followed or trusted.
Invalid local input or missing credentials causes no write; a connection failure
before attempting creation is reported as `not_attempted`.

**Each live invocation creates a new case.** The API does not document an
idempotency key; this action does not search for duplicates or update existing
cases. Prefer a trigger that runs once per event or manage repeated execution in
your workflow. A timeout, HTTP error, invalid JSON or unconfirmed acknowledgement
produces an error with `data.success: false` and `data.status: uncertain`. Check
the configured Tines team for the event UUID before manually retrying: the case
may already have been created. There is no automatic retry or fallback to v1.

## References

- [API welcome](https://www.tines.com/stories/docs/api/welcome/)
- [Authentication and API key scopes](https://www.tines.com/stories/docs/api/authentication/)
- [Cases v2 create](https://www.tines.com/stories/docs/api/cases/create/)
- [Cases OpenAPI specification](https://www.tines.com/cases/docs/api/openapi.json)
