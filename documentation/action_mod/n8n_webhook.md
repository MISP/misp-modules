# n8n Webhook

`n8n_webhook` delivers one selected MISP event to a POST
[Webhook trigger](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/).
This starts your published n8n workflow using the selected data. The public
`/api/v1` workflow API manages workflows; it does not offer a general endpoint
to start a workflow with an event payload. No private `/rest` endpoints are used.

## Configure n8n and the module server

1. Create an n8n workflow with a **Webhook** trigger, HTTP method **POST**.
2. Select **Header Auth** and create a dedicated credential, for example header
   `X-MISP-Token` with a randomly generated secret.
3. Publish the workflow. Copy the node's **Production URL**.
4. Configure the following environment variables on the misp-modules server,
   then restart its process:

| Variable | Meaning |
| --- | --- |
| `N8N_WEBHOOK_URL` | Exact HTTPS production webhook URL. Custom endpoints, subpaths and a trailing slash are preserved. No embedded credentials, query string or fragment. |
| `N8N_WEBHOOK_HEADER_NAME` | Header credential name; default `X-MISP-Token`. Supports `Authorization` or an `X-` header except reserved routing/method, public API key and payload digest headers. |
| `N8N_WEBHOOK_HEADER_VALUE` | Required dedicated webhook secret matching the n8n credential. For an Authorization header, include any scheme, such as `Bearer `. |
| `N8N_WEBHOOK_TIMEOUT` | Request timeout, 1–120 seconds; default 20. |

The public API's `X-N8N-API-KEY` does not authenticate a Webhook node and cannot
be used as the action's header name. Workflow parameters and query `config`
cannot override server connection settings. Keys, webhook URLs and response
bodies are not returned. Standard requests proxy settings, certificate validation
and `REQUESTS_CA_BUNDLE` are preserved. Redirects and automatic retries are disabled.

Test URLs can be configured temporarily during development, but require n8n to
be listening for a test event. Use the production URL for unattended workflows.

## MISP workflow parameters

| Parameter | Meaning |
| --- | --- |
| `dry_run` | Default true. Returns the preview without credentials or network access. Set explicitly to false to deliver once. Missing, null or empty values preview. |
| `to_ids_only` | Default false. Set true to send only attributes marked `to_ids`. |

Pass exactly one selected event, with valid event, object and attribute UUIDs.
Bare events, `{"Event": {...}}`, a one-element list and legacy core-format
envelopes with selected `Attribute`/`Object` collections beside `Event` are
supported. Workflow filters and multiple selected events are rejected. Requests
containing `filteredItems` or `matchingData` are rejected by key presence, including
null or empty selections. Supply an explicit selected event in `data`; the module
never falls back from extracted workflow data to a broader event.

Example `/query` request:

```json
{
  "module": "n8n_webhook",
  "params": {"dry_run": "true", "to_ids_only": "false"},
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "info": "Selected MISP event",
      "Attribute": [{
        "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
        "type": "domain",
        "value": "example.org",
        "to_ids": true
      }]
    }
  }
}
```

## Payload contract

The webhook receives JSON with `source: "misp-modules"`, `version: 1` and `Event`.
In n8n, access it as `$json.body.Event` after the Webhook trigger. `Event` includes
its UUID, optional `info`, and selected `Attribute` and `Object` arrays:

- Attributes contain `uuid`, `type`, `value`, boolean `to_ids`, and optional
  `category` and `object_relation`.
- Objects contain `uuid`, `name` and selected attributes.
- Deleted events are rejected; deleted objects/attributes, `attachment` and
  `malware-sample` attributes are excluded. Empty objects are omitted.
- Other fields, including binary `data`, comments, tags and object references,
  are not copied. Attribute values and the event title are sent to n8n.

At most 1000 selected attributes and 1 MiB of encoded JSON are accepted per call.
The module validates the complete selection before sending anything and preserves
source values without hash, domain or IP normalization. Counts describe the
workflow selection, rather than necessarily the entire source event.

## Delivery, execution and retries

The result uses `result_key: n8n_webhook`. Preview returns `data.status: planned`
and the payload. Live delivery returns `data.status: delivered`, the HTTP status,
selected/skipped counts and `payload_sha256` after a 2xx response. Response bodies
are discarded. `execution_confirmed` is always false: immediate webhook replies,
custom responses and n8n's Only Run If option cannot prove downstream completion.
Use n8n's execution history or a separate callback for execution outcomes.

The SHA-256 of the canonical payload is also sent as `X-MISP-Payload-SHA256`.
Your workflow can use this digest and the source UUIDs for duplicate handling.
It is not an automatic idempotency guarantee. Public API `Idempotency-Key`
support does not apply to this webhook action.

A local configuration failure is `not_attempted`. A network failure, timeout or
non-2xx reply returns an error with `data.success: false` and status `uncertain`.
The workflow may already have started. Inspect n8n executions before retrying;
there are no automatic retries. Throttle workflow calls to suit your n8n plan
and instance capacity.

## References

- [Public API](https://docs.n8n.io/connect/n8n-api)
- [Webhook trigger and response modes](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/)
- [Webhook credentials](https://docs.n8n.io/integrations/builtin/credentials/webhook/)
- [Public API idempotency scope](https://docs.n8n.io/connect/n8n-api/idempotency)
