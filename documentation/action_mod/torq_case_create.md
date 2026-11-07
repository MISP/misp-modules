# Torq Case Create

`torq_case_create` creates one Torq case referencing one selected MISP event using
[`POST /public/v1alpha/cases`](https://developers.torq.io/apidocs/create-a-case).
It sends an event UUID, selected-data counts and provenance tags. It does not
export the full event or synchronize an existing case.

## Module-server configuration

Set the following environment variables on the **misp-modules server**, then
restart its process:

| Variable | Meaning |
| --- | --- |
| `TORQ_REGION` | `us` (default), `eu` or `jp`. The API key/token must belong to the intended workspace in that region. |
| `TORQ_CLIENT_ID`, `TORQ_CLIENT_SECRET` | Torq API key pair for automatic token exchange in US/EU. |
| `TORQ_ACCESS_TOKEN` | Alternatively, an existing bearer token. Do not set the client credential pair at the same time. Required for JP. |
| `TORQ_TIMEOUT` | Timeout per request, 1–120 seconds; default 20. |
| `TORQ_MISP_URL` | Optional HTTPS source MISP base URL, including a deployment subpath. No embedded credentials, query or fragment. |

Use a Torq API key permitted to create cases in the intended workspace. Torq keys
are workspace-specific; there is no workspace override in the request. Workflow
parameters and query `config` cannot override server connection settings.

The client uses fixed documented regional bases:

| Region | API base | Automatic token endpoint |
| --- | --- | --- |
| `us` | `https://api.torq.io/public` | `https://auth.torq.io/v1/auth/token` |
| `eu` | `https://api.eu.torq.io/public` | `https://auth.eu.torq.io/v1/auth/token` |
| `jp` | `https://api.jp.torq.io/public` | Supply `TORQ_ACCESS_TOKEN`. |

The authentication guide documents US/EU token endpoints. JP API calls are
supported with an existing token, without assuming a JP authentication endpoint.
Torq tokens normally expire after one hour; operators must renew supplied tokens.
Client-credentials mode obtains a fresh token per invocation using HTTP Basic
authentication and form field `grant_type=client_credentials`. Tokens are not
cached between invocations or returned in results/errors.

HTTPS verification, standard requests proxy settings and `REQUESTS_CA_BUNDLE`
are preserved. Redirects and automatic retries are disabled. Each response has a
2 MiB limit. Torq documents a limit of 50 API requests per second; configure MISP
workflow execution rates to fit the workspace's overall usage.

## Workflow parameters

| Parameter | Meaning |
| --- | --- |
| `reporter_email` | Required ASCII email address of the Torq case reporter. The API validates the reporter's eligibility. |
| `title_prefix` | Default `MISP event`; 1–64 ASCII letters, digits, spaces, `.`, `_` or `-`. The event UUID is appended. |
| `severity` | `informational`, `low`, `medium`, `high` or `critical`, case insensitive; default `medium`. |
| `dry_run` | Default true. Set explicitly to false to create a case. Missing, null and empty values preview. |

Dry runs require no credentials and perform no network calls. If
`TORQ_MISP_URL` is configured, it is validated for previews as well as creation.

Supply exactly one non-deleted MISP event with a valid UUID. Bare events,
`{"Event": {...}}`, a one-element list and legacy core-format envelopes with
selected `Attribute`/`Object` collections beside `Event` are supported. Multiple
events and workflow filters are rejected. `filteredItems` and `matchingData`
are rejected by key presence, including null/empty values, so extracted selections
cannot fall back to a broader event. Supply the explicit selection in `data`.

Example `/query` request:

```json
{
  "module": "torq_case_create",
  "params": {
    "reporter_email": "analyst@example.org",
    "severity": "medium",
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

## Case payload and results

The API payload includes:

- `title`: prefix plus the event UUID;
- `description`: the UUID, counts of active selected attributes/objects/IDS
  attributes and an optional source link to `/events/view/<uuid>`;
- `state: {"value": "new"}`;
- `severity: {"value": "medium"}` or the selected severity;
- `reporter: {"user": {"email": "analyst@example.org"}}`;
- tags `misp` and `misp-event:<uuid>` for provenance.

Counts describe the workflow selection, including attributes in active objects.
Deleted attributes/objects are excluded; active attachments count as attributes,
but their contents are never sent. Missing `to_ids` means false. Event titles,
observable values, comments, existing tags, user mentions and binary attachments
are not copied. The module does not associate observables, assign users, select a
runbook or request case-resolution actions.

The result uses `result_key: torq_case_create`. Preview returns status `planned`
and the exact API payload. A live invocation authenticates, then attempts one
case-creation POST. Torq documents **HTTP 200**, with a `case` object, as success.
The module checks the positive case ID, title, event reference, reporter, state,
severity and provenance tags before returning status `created`, case ID and
optional `pretty_id`. It does not invent a UI link.

**Each live invocation creates a new case.** No native idempotency mechanism is
documented for this endpoint; the module does not search for duplicates or update
existing cases. Use a once-per-event trigger or manage duplicates in your own
workflow using the source UUID/provenance tag.

Input, configuration and authentication failures cause no case write. Connection
or authentication failures before the creation call report `not_attempted`.
A timeout, HTTP error, malformed reply or unconfirmed case acknowledgement after
attempting creation returns an error with `data.success: false` and status
`uncertain`. Inspect Torq for the source UUID before retrying: the case may already
exist. There are no automatic retries or token-refresh retries of a case write.

## References

- [API overview, regional bases and rate limits](https://developers.torq.io/apidocs/overview)
- [Authentication](https://developers.torq.io/apidocs/authentication)
- [Create a case: request and response schemas](https://developers.torq.io/apidocs/create-a-case)
