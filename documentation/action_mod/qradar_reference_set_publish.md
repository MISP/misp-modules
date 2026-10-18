# QRadar Reference Set Publish

`qradar_reference_set_publish` is a blocking workflow action that adds or refreshes
selected MISP indicators in an existing QRadar reference set and an explicit domain.
It uses the current **API 20.0** `reference_data_collections` endpoints. It shares
validation and normalization with [QRadar Reference Set Export](../export_mod/qradar_reference_set_export.md),
which produces offline CSV or JSON files. Different names allow both modules to
appear in the module server's registry.

## Setup

1. Create a dedicated reference set in QRadar with a compatible entry type, and
   configure its expiry policy. Find its numeric ID through QRadar's API explorer
   at `/api_doc`, using `GET /reference_data_collections/sets`.
2. Create an authorized service token whose role and security profile permit
   reading the selected set and adding/updating entries in the intended domain.
   Confirm that your QRadar installation supports API 20.0.
3. Configure `QRADAR_URL` as an HTTPS console origin, for example
   `https://qradar.example`, and `QRADAR_API_TOKEN` in the environment of the
   **misp-modules service**. Restart that service. The URL must not contain
   credentials, an API path, a query or a fragment.
4. For a private certificate authority, optionally set `QRADAR_CA_BUNDLE` to a PEM
   CA bundle accessible to the service. TLS verification remains enabled; the
   module provides no option to disable it.
5. Enable **QRadar Reference Set Publish** and add it to a workflow supplying the
   intended events and object attributes. Preview with `dry_run=true`, then set it
   to `false` to publish. Dry runs need no credentials and cannot verify set types,
   domain permissions or existing values.

Credentials, console URL and CA trust are server settings. Workflow parameters
cannot change them. The token is sent in the `SEC` header and the API version is
explicitly pinned with `Version: 20.0`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `reference_set_id` | Required | Positive numeric ID of an existing reference set. Names and arbitrary paths are not accepted. |
| `domain_id` | Required | Explicit non-negative domain ID, or `SHARED` to publish shared reference data. `0` is QRadar's Default Domain, distinct from shared data. `SHARED` is sent as JSON `null`; neither scope is chosen implicitly. |
| `indicator_type` | `ipv4` | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` or `sha512`. |
| `source` | `misp-modules` | Entry source label, 1–64 ASCII letters, digits, spaces or `._:/-`, starting with a letter or digit. |
| `dry_run` | `false` | Preview per-entry JSON payloads without network access. |

Boolean values accept JSON booleans, integers 0/1 and strings `true`, `false`, `1`,
`0`. Empty optional settings use defaults. IDs accept integers or digit strings.
MISP displays node defaults as placeholders; the module also applies them when
values are omitted. Shared reference data can be visible across tenants; select
`SHARED` only when that is the intended scope.

## Input and set compatibility

The action accepts standard, bare or legacy event envelopes, singly or in a list,
and traverses their object attributes. Only non-deleted `to_ids=true` attributes
are eligible. Deleted events and objects are excluded. No non-IDS override is
available for publication. Only supplied attributes are considered; missing data
is not fetched from MISP.

The selected type, normalization and supported composites are described in the
[export guide](../export_mod/qradar_reference_set_export.md#supported-indicators-and-target-types).
Before writing anything, the action fetches `GET /reference_data_collections/sets/{id}`
and confirms the returned set ID and `entry_type`:

| Selected type | Required set entry type |
| --- | --- |
| `ipv4` | `IP` |
| `ipv6`, `url` | `ALN` |
| `domain`, `md5`, `sha1`, `sha256`, `sha512` | `ALN` or `ALNIC` |

This prevents IPv6 from being sent to an IPv4 set and URLs from being stored in a
case-insensitive set. A text set cannot identify its intended semantic use, so use
dedicated sets and select the intended type. The caller must have access to the
chosen collection and domain; QRadar validates that authorization on each write.

Unsupported, malformed and other-type attributes are skipped with counts.
Canonical values are deduplicated within an invocation. All contributing MISP
event, attribute and object references remain in the returned `sources` lists.
Only value, collection ID, domain ID and the configured source label are sent to
QRadar. Comments, tags, event titles, provenance notes and sample data are not sent.
Select inputs according to MISP sharing and handling policy.

The action advertises `support_filters=false`. Payloads containing `filteredItems`
or `matchingData` fail rather than silently publishing unfiltered events. Select
the intended data upstream.

## Publication and lifecycle

Each value is submitted using `POST /reference_data_collections/set_entries`:

```json
{"collection_id": 42, "domain_id": 7, "source": "misp-modules", "value": "192.0.2.1"}
```

QRadar returns HTTP **201** for a created entry and **200** for an updated entry.
The action counts success only when the returned numeric entry ID, collection ID,
domain ID, value and source confirm the submitted payload. Missing or mismatched
acknowledgements fail with an unknown-outcome message. A 202 asynchronous response
is not treated as success; the action uses synchronous per-entry requests.

This is an add/update operation on the explicitly chosen set. An existing matching
value can be updated even if another publisher supplied it, including its source
metadata. The source label is not an ownership guard. Use a dedicated set/domain
when other publishers must remain independent. Repeated publication follows
QRadar's entry update behavior and the set's existing `FIRST_SEEN`, `LAST_SEEN` or
`NO_EXPIRY` policy. The module does not set timestamps or promise a per-IOC lifetime.

The action does not create sets, change their type or TTL, purge values, or delete
entries. Removing an attribute from MISP or marking it non-IDS does not withdraw
it from QRadar. Use the set's configured expiry or separate administration for
withdrawal. Reference-set membership takes effect in the rules configured to use
that set; publication does not create QRadar rules or automatically block traffic.

## Workflow/API example

POST to the misp-modules `/query` endpoint for a preview:

```json
{
  "module": "qradar_reference_set_publish",
  "params": {
    "reference_set_id": "42",
    "domain_id": "7",
    "indicator_type": "ipv4",
    "source": "MISP production",
    "dry_run": "true"
  },
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "ip-dst",
        "value": "192.0.2.1",
        "to_ids": true
      }]
    }
  }
}
```

Responses contain `result_key=qradar_reference_set_publish` and a `data` summary
with `success`, selected target/type/source, `dry_run`, `created`, `updated`,
`planned`, `failed`, `skipped` and `items`. Items identify each value, its sources
and status; live successes include the remote entry `id`, and dry-run items include
the planned payload. Successful summaries are available under
`_env.misp_module_results.qradar_reference_set_publish`.

Preflight target failures return a top-level `error` with `success=false`, before
any value is attempted. Per-entry failures also return `error`, preserve completed
outcomes and set `success=false`. **Publication may be partial.** The blocking
action stops dependent workflow execution on failure. MISP may retain only the
top-level error on failure; standalone API callers receive the full summary.
HTTP errors, redirects, invalid JSON and malformed acknowledgements are reported
without returning provider error bodies or exception text.

## Limits and validation

At most **100 unique selected values** are accepted per action invocation; larger
inputs fail before network access. Split larger selections. Requests use a
15-second timeout; a 240-second processing budget is checked after the target
lookup and before each write. TLS is verified and redirects are disabled. Rate
limits and uncertain responses fail without automatic retries or rollback.
Check QRadar before retrying an uncertain write.

Tests cover normalization, real `requests` serialization through mocked HTTP
transport, discovery/query endpoints, target validation, acknowledgements and
partial failures. No live QRadar tenant was used; verify permissions, set expiry
and deployment-specific behavior before enabling publication. Existing MISP
`file` and `domain-ip` objects suffice; no new templates are needed.

References: [API 20.0 entry creation/update](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-set_entries-POST.html),
[set metadata](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-sets-id-GET.html),
and [authorized service authentication](https://ibmsecuritydocs.github.io/qradar_api_overview/c_rest_api_getting_started.html).
