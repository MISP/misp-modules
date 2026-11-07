# Shuffle Workflow Execute

`shuffle_workflow_execute` submits one selected MISP event to the documented
`POST /api/v1/workflows/<workflow_id>/execute` endpoint. It sends the selected data
as a JSON-encoded **string** in `execution_argument` and uses the workflow's
configured start node (`start: ""`).

## Module-server configuration

Set these environment variables on the **misp-modules server**, then restart its
process:

| Variable | Meaning |
| --- | --- |
| `SHUFFLE_URL` | Required HTTPS API root ending in `/api/v1`, e.g. `https://uk.shuffler.io/api/v1`. Self-hosted hosts, ports and deployment subpaths are supported. |
| `SHUFFLE_API_KEY` | Shuffle API key permitted to execute the target workflow in the intended organization. Sent as `Authorization: Bearer <key>`. |
| `SHUFFLE_ORG_ID` | Required organization UUID, sent in the documented `Org-Id` header. |
| `SHUFFLE_TIMEOUT` | Request timeout in seconds, 1–120; default 20. |

Use the API root for the account's current region. Shuffle documents UK,
Frankfurt, California and Canada hosts, plus an Australia test region. The same
API supports self-hosted installations. URLs must use HTTPS without embedded
credentials, query strings or fragments. Redirects are refused, so select the
correct regional endpoint rather than relying on a redirect.

Workflow parameters and query `config` cannot override server connection or
organization settings. HTTPS verification, standard requests proxy settings and
`REQUESTS_CA_BUNDLE` are preserved. API responses are limited to 2 MiB. API keys,
execution authorization tokens and arbitrary provider response data are never
included in the result.

## MISP workflow parameters

| Parameter | Meaning |
| --- | --- |
| `workflow_id` | Required UUID of the Shuffle workflow to execute. Shuffle enforces the API account's access to this workflow. |
| `dry_run` | Default true. Returns the preview without credentials or network access. Set explicitly to false to submit a new run. Missing, null and empty values preview. |
| `to_ids_only` | Default false. Set true to include only attributes marked `to_ids`. |

Supply exactly one non-deleted event, with valid event, object and attribute UUIDs.
Bare events, `{"Event": {...}}`, a one-element list and legacy core-format
envelopes with selected `Attribute`/`Object` collections beside `Event` are
supported. Multiple events and workflow filters are rejected. Requests containing
`filteredItems` or `matchingData` are rejected by key presence, including empty or
null values. Supply an explicit selected event in `data`; extracted selections
never fall back to a broader event.

Example `/query` request:

```json
{
  "module": "shuffle_workflow_execute",
  "params": {
    "workflow_id": "8f3c6a10-f5ca-432c-aef9-c5e038166c45",
    "dry_run": "true",
    "to_ids_only": "false"
  },
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

## Execution argument contract

After JSON-decoding `execution_argument`, the Shuffle workflow receives
`{"source": "misp-modules", "version": 1, "Event": {...}}`. `Event` includes its
UUID, optional `info`, and selected `Attribute`/`Object` arrays:

- Attributes contain `uuid`, `type`, `value`, boolean `to_ids`, and optional
  `category` and `object_relation`.
- Objects contain `uuid`, `name` and their selected attributes.
- Deleted attributes/objects, `attachment` and `malware-sample` attributes are
  excluded. Empty objects are omitted.
- Binary `data`, comments, tags, object references and other unselected fields
  are not copied. Selected observable values and the event title are sent.

Source values are preserved without hash, domain or IP normalization. The
complete selection is validated before submission. At most 1000 attributes and
1 MiB of encoded execution-argument JSON are accepted per call; the outer API
request wraps that JSON in a string. Counts describe the selection, rather than
necessarily the complete source event. The SHA-256 of the canonical argument
string is included as `payload_sha256` in the MISP result for comparison/auditing.

The module sends only `execution_argument` and `start: ""`. It does not select an
alternate starting node, inject app-authentication overrides, select another
runtime environment or supply a callback URL.

## Submission, completion and retries

The result uses `result_key: shuffle_workflow_execute`. Preview returns status
`planned` and the exact API payload, including the string-valued argument. A live
invocation requires HTTP 200, boolean `success: true` and a valid returned
`execution_id`. If the reply also identifies a workflow, it must match the
requested one. The result then reports status `submitted`, execution ID, workflow
ID, organization, source event UUID and selected/skipped counts.

`execution_complete` is always false. An accepted execution ID confirms
submission, rather than downstream completion or successful workflow results.
The action waits only for the submission response and does not poll. Shuffle's
separate `/streams/results` API requires the execution authorization token in its
request body; that token is intentionally not exposed by this module. Inspect
Shuffle's execution history to track the run.

Each live invocation submits a new execution. No native idempotency guarantee is
documented for this operation; the module does not retry automatically or reuse
an execution ID. Handle repeated source UUIDs/payloads in your workflow if needed.

Input/configuration failures cause no execution request. Connection configuration
failures report `not_attempted`. A timeout, HTTP error, malformed reply or
unconfirmed acknowledgement after attempting submission returns an error with
`data.success: false` and status `uncertain`. Check Shuffle executions before
retrying: a run may already exist.

## References

- [Shuffle API](https://shuffler.io/docs/API)
- [Official documentation: execute workflow](https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md#execute-workflow)
- [Official documentation: execution results](https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md#get-execution-results)
