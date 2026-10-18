# Microsoft Sentinel direct publishing

Microsoft Sentinel indicators can now be published directly from supplied MISP
events and object attributes, without installing MISP2Sentinel or executing a
local integration script. Two action entry points share the same implementation:

- **`sentinel_publish`** is the dedicated, blocking direct-publishing action.
- **`export_sentinel`** supports direct publishing with `mode=direct`. Its default
  remains `mode=wrapper`, for existing MISP2Sentinel/MISP2Defender installations.

Direct publishing targets Microsoft's current **STIX objects upload API**, version
`2024-02-01-preview`, in the commercial Azure cloud. Microsoft documents this API
as preview. The module uses the existing `requests` dependency; it does not use
the legacy upload-indicators endpoint or the retired Graph TI submission path.
Direct mode publishes to Sentinel; Defender publishing remains available through
the existing wrapper mode.

## Configure direct publishing

1. Register a Microsoft Entra application and create a client secret. Grant that
   application's service principal **Microsoft Sentinel Contributor** at the
   intended Log Analytics workspace.
2. Configure `SENTINEL_TENANT_ID`, `SENTINEL_CLIENT_ID` and
   `SENTINEL_CLIENT_SECRET` in the environment of the **misp-modules service**,
   then restart it. Tenant/client IDs must be non-nil UUIDs. Credentials are not
   accepted as workflow parameters.
3. Enable **Microsoft Sentinel Publish**, or choose **Export to Sentinel or
   Defender** with `mode=direct`. Supply the full intended events and objects in
   workflow data and set the target workspace UUID.
4. Preview with `dry_run=true`, inspect the STIX objects and scope, then set it to
   `false` to publish. Dry runs need no credentials and make no network calls;
   they cannot validate Entra roles or tenant-specific API behavior.

The workspace ID is the **Log Analytics workspace UUID**, not its Azure resource
ID, subscription ID or display name. Endpoint URLs and token audience are fixed:

```text
POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
scope = https://management.azure.com/.default

POST https://api.ti.sentinel.azure.com/workspaces/{workspaceId}/threat-intelligence-stix-objects:upload
api-version = 2024-02-01-preview
```

The Entra request uses OAuth client credentials. A fresh token is obtained once
per invocation; it must have enough remaining lifetime for the publication
budget. The token and secret are never returned or included in upload payloads.
TLS verification is enabled and redirects are disabled on both endpoints. This
implementation does not support sovereign cloud endpoints, interactive login,
certificate credentials or managed identity.

| Direct parameter | Default | Meaning |
| --- | --- | --- |
| `workspace_id` | Required | Explicit target workspace UUID. |
| `source` | `misp-modules` | Stable `sourcesystem` label, 1–64 ASCII letters, digits, spaces or `._:/-`, beginning with a letter/digit. The API reserves `Microsoft Sentinel`. |
| `expiration_days` | `30` | Integer 1–365; set each indicator's `valid_until` from the publication time. |
| `confidence` | `50` | STIX confidence, integer 0–100. |
| `dry_run` | `false` | Return planned request bodies and outcomes without authentication or upload. |

Boolean values accept JSON booleans, integers 0/1 and strings `true`, `false`, `1`,
`0`. Empty optional values use the documented defaults. MISP displays node
defaults as placeholders; the module also applies them when values are omitted.

## Inputs and conversion

`data` accepts one standard (`{"Event": {...}}`), bare or legacy event envelope,
or a list of those events. Object attributes are traversed. Only supplied
`to_ids=true`, non-deleted attributes are eligible; deleted events and objects
are excluded. The direct publisher does not fetch additional MISP data.

Every eligible attribute needs a valid **UUID** and **Unix-seconds `timestamp`**.
These are present in normal MISP core event exports and identify a source
revision. Missing, invalid or future-dated timestamps and malformed UUIDs are
counted as malformed rather than assigned unstable fallback identities. Ensure
upstream data includes those fields when supplying custom event JSON.

| MISP type | STIX pattern path | Conversion |
| --- | --- | --- |
| `md5`, `sha1`, `sha256`, `sha512` | `file:hashes.'MD5'`, `'SHA-1'`, `'SHA-256'`, `'SHA-512'` | Validate hexadecimal length and lowercase. |
| `domain`, `hostname` | `domain-name:value` | IDNA encode, lowercase, remove one trailing DNS dot, validate labels and the 253-character normalized name limit. |
| `ip-src`, `ip-dst` | `ipv4-addr:value` or `ipv6-addr:value` | Validate and canonicalize; CIDRs and scoped IPv6 are excluded. |
| `url` | `url:value` | Require absolute HTTP(S) without credentials, whitespace or controls; retain the exact value. |
| `email`, `email-src`, `email-dst` | `email-addr:value` | Accept a bare ASCII local part and valid IDNA domain; retain local-part case. |
| `domain\|ip` | Domain plus IP | Validate both components and publish two independent indicators. |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `filename\|sha512`, `malware-sample` | File hash | Publish only the hash component, splitting at the last pipe. No sample or filename data is uploaded. |

Values are quoted and escaped for STIX patterns. Unsupported types, including
filenames alone, port-qualified composites and other rule languages, are skipped.
Port constraints are not discarded to create broader indicators. Malformed values
are skipped with counts; malformed containers and configuration fail before
network access. Existing `file` and `domain-ip` objects are supported, so no new
MISP object templates are required.

Event, object and attribute tags are combined as STIX labels. Standard TLP
white/clear, green, amber and red tags also produce the corresponding STIX TLP
marking references; clear maps to the equivalent white definition. Other handling
tags remain labels, including TLP extensions for which this implementation has no
marking-definition mapping. The destination's treatment of markings is not an
access-control guarantee: select the workspace and input according to MISP
sharing and handling policy.

Source event/attribute/object identifiers are retained in descriptions and result
`sources`, and attributes have MISP external references. Free-text event titles,
comments and binary sample data are not copied. Duplicate representations of the
same source revision and normalized pattern are combined within an invocation.
Different MISP attribute UUIDs remain independent indicators, even if they contain
the same observable.

## Identity and lifecycle

A deterministic STIX `indicator--UUID` is derived from workspace, source namespace,
attribute UUID, attribute timestamp and normalized pattern. The source revision's
timestamp supplies `created` and `valid_from`; publication time supplies `modified`.
Re-running an unchanged source revision keeps its ID and creation time while
submitting a newer modification time and expiry. Changing confidence or expiry
does not change that revision's identity.

Changing the attribute timestamp, UUID, normalized pattern, source or workspace
creates a different identity. This makes source revisions independent and avoids
changing the immutable creation timestamp of a reused STIX ID. Older revisions
are not automatically revoked, and separate attributes with equal observables
can coexist. Keep source labels stable and use the configured expiry or separate
Sentinel administration to withdraw old records. Deleted/non-IDS input is not a
deletion instruction. The module does not query existing indicators, claim
ownership of existing records, or guarantee exactly-once ingestion.

## API example

POST to the misp-modules `/query` endpoint for a preview:

```json
{
  "module": "sentinel_publish",
  "params": {
    "workspace_id": "22549473-0938-4938-8a04-225494730938",
    "source": "MISP production",
    "expiration_days": "30",
    "dry_run": "true"
  },
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "timestamp": "1767225600",
        "type": "domain",
        "value": "example.org",
        "to_ids": true
      }]
    }
  }
}
```

To use the existing entry point, change `module` to `export_sentinel` and add
`"mode": "direct"` to `params`. Both direct entry points return
`result_key=sentinel_publish` and the same `data` summary: `success`, `dry_run`,
`workspace_id`, `uploaded`, `failed`, `planned`, `skipped` and `items`. Items include
the STIX ID, sources, status and sanitized failure information. Dry runs include
the exact planned API bodies under `payloads`.

Successful workflow summaries are stored under
`_env.misp_module_results.sentinel_publish`. A top-level `error` signals failure;
MISP may then retain only the error, while standalone API callers receive the
full per-item summary. Prefer the dedicated **blocking** `sentinel_publish` action
when downstream workflow steps depend on complete publication. `export_sentinel`
keeps its existing non-blocking configuration for compatibility.

### Upload acknowledgements and limits

Microsoft documents a maximum of **100 objects per request** and **100 requests
per minute**. The module accepts at most **1,000 unique source-revision indicators**
per invocation and splits them into batches of up to 100. A local **1 MiB per-batch**
limit is checked before authentication; split large inputs or reduce tag metadata
if needed. Calls have a 15-second timeout and a 240-second publication budget.

An HTTP 200 with an empty body confirms validation/publication of that batch.
HTTP 200 can also contain an `errors` array whose zero-based `recordIndex` values
identify failed STIX objects. The module validates those indices and maps failures
back to the matching items; other objects in that batch are counted as uploaded.
An empty error list is accepted. Unexpected response shapes, duplicate/out-of-range
indices, malformed JSON and non-200 responses fail without treating the batch as
successful.

Unknown/unsuccessful batch outcomes stop subsequent batches, which are reported
as not attempted in their error messages. Indexed validation failures can coexist
with successful objects and do not prevent later batches from being submitted.
There are no automatic retries or rollbacks. **Publication can be partial.** Check
Sentinel before retrying an uncertain request. Counts describe upload API
acceptance, not immediate query visibility, newly created versus updated records,
analytics-rule matches or blocking enforcement. Provider error bodies and Entra
exception details are not exposed in results.

## Existing wrapper compatibility

`export_sentinel` keeps `mode=wrapper` as its default and continues to call the
configured Python executable with the event UUID as a single argument:

```text
{misp2_venv}/bin/python {misp2_script} {event_uuid}
```

The existing `misp2_venv` and `misp2_script` parameters retain their default paths:
`/var/www/MISP/misp-custom/misp2sentinel/venv/` and
`/var/www/MISP/misp-custom/misp2sentinel/script.py`. Empty values now apply those
defaults. Paths must be absolute, the executable/script must exist, and the input
must identify one event with a valid UUID. The script's directory remains the
working directory. Successful wrapper calls retain `{"data": true}`.

Wrapper failures now return `data=false` **and a top-level error**, so failures
are visible to MISP instead of appearing as a successfully executed action. The
timeout is 240 seconds to fit inside the module server's normal timeout. Script
stdout/stderr are suppressed rather than copied into service logs; configure the
integration script's own logging for diagnostics. Wrapper mode has no dry run.
Its installed integration still controls refetching, filters and remote API use.

Both entry points advertise `support_filters=false` and reject `filteredItems` or
`matchingData` payloads. The old wrapper advertised filter support but never
applied it; it refetched the event by UUID. Select intended events upstream and
configure any wrapper-side selection in MISP2Sentinel/MISP2Defender itself.

## Validation

Tests validate STIX objects and patterns, current OAuth/upload wire contracts with
mocked HTTP transport, batching and indexed partial failures, credential handling,
source revision identities, objects and workflow discovery/query endpoints.
Wrapper tests cover the original argument/working-directory contract and execute
a harmless local script through a test virtual environment. No live Sentinel
workspace or Defender tenant was changed; verify credentials, workspace roles,
marking treatment and preview API availability in your deployment.

References: [Microsoft STIX upload API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api),
[application/workspace setup](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api),
and [MISP2Sentinel](https://github.com/cudeso/misp2sentinel).
