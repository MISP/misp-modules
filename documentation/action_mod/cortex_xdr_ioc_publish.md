# Cortex XDR IOC Publish

`cortex_xdr_ioc_publish` is a workflow action that uploads IDS-marked MISP
observables as Cortex XDR IOC rules. It defaults to a credential-free preview.
Set `dry_run=false` to enable API lookups and uploads.

The module uses `indicators/get` to check the exact type/value before each
upload, and `indicators/insert_jsons` with `validate=true` for missing rules.
It does not use WildFire or PAN-OS APIs. The gateway traffic collectors described
in Palo Alto's [API Security guide](https://cortex-docs.paloaltonetworks.com/cortex-xdr/configure-cortex-xdr/cortex-xdr-data-sources/vendor-specific-data-sources/api-security)
are separate from these IOC rule APIs.

## Server configuration

Configure these environment variables on the module server:

| Variable | Meaning |
| --- | --- |
| `CORTEX_XDR_URL` | Tenant API HTTPS origin copied from API Keys, with no endpoint path, credentials, query or fragment. |
| `CORTEX_XDR_API_KEY` | API key value. |
| `CORTEX_XDR_API_KEY_ID` | Matching API key ID as a string of digits. |
| `CORTEX_XDR_AUTH_TYPE` | `advanced` (default) or `standard`, matching the key's security level. |

Creating IOC rules requires **Cortex XDR Pro**. The key needs access to IOC lookup and upload. The lookup reference explicitly
requires **Rules Edit** permission. Cortex XDR licensing and RBAC remain enforced
by the tenant. Connection settings cannot be supplied or overridden in workflow
parameters. No additional Python dependency or MISP object template is required.

## Workflow parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `source` | `misp-modules` | Stable publisher label, 1–64 ASCII letters/digits/spaces or `._:/-`, starting with a letter/digit. |
| `severity` | `MEDIUM` | `INFO`, `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`. |
| `reputation` | `SUSPICIOUS` | `SUSPICIOUS` or `BAD`, explicitly applied to new uploads. |
| `expiration_days` | `30` | Explicit lifetime of `7`, `30`, `90` or `180` days. |
| `dry_run` | `true` | Preview payloads without reading credentials or contacting the tenant; `false` enables publication. |

Empty optional parameters use these defaults. Booleans accept JSON booleans,
integers 0/1 and strings `true`, `false`, `1`, `0`. A MISP detection flag selects
an observable for publication; the configured reputation is a separate operator
choice. Preview payloads include the selected severity, reputation and expiry.

## Input selection and normalization

`data` accepts standard `{"Event": {...}}` events, bare events, legacy envelopes
with collections beside `Event`, or a list of these. Event and object attributes
are included only when `to_ids=true` and neither the event, object nor attribute
is deleted. Source attributes need valid UUIDs for provenance.

Supported types are `md5`, `sha256`, `domain`, `hostname`, `ip-src` and
`ip-dst`. Hashes are checked and lowercased; IPs are canonicalized; domains use
non-transitional IDNA2008/UTS-46 processing, preserving distinct identities such
as `faß.de` and `fass.de`. CIDRs, scoped IPv6, wildcards, URLs, filenames and
composites and SHA-1 hashes are unsupported. The module does not discard ports or other
constraints to broaden an indicator. Unsupported and malformed attributes have
separate skipped counts; malformed containers fail before network access.

Canonical type/value pairs are deduplicated, retaining contributing event,
object and attribute UUIDs in `sources`. The remote comment contains only the
publisher label and attribute UUIDs, limited to 500 characters. Full provenance
remains in the result. Event titles, attribute comments, tags and binary data
are not uploaded. At most 50 unique indicators are accepted per invocation;
larger selections fail before any request. `filteredItems` and `matchingData`
are rejected because workflow filters are unsupported; select events upstream.

## Existing rules, lifecycle and acknowledgement

Any exact matching rule observed during preflight is reported as `existing`
and left unchanged, regardless of its comment/source, severity or expiry.
Existing results include rule IDs and available metadata. The native
`expiration_date: -1` sentinel for non-expiring rules is preserved. This action
does not renew expired records, reactivate disabled rules, delete rules or
withdraw records when MISP attributes are deleted or lose their detection flag.
Use tenant administration for those lifecycle operations. `existing` does not
guarantee that a rule is currently active.

Each upload contains one IOC and `validate=true`. Success requires an explicit
`reply.success=true` and no reported validation errors; a bare `reply=true` is
not accepted as a confirmed upload. A single-IOC request prevents an aggregate
"any uploaded" acknowledgement from being mistaken for batch-wide success.
Successful results use `uploaded`, rather than claiming an atomic create.

Preflight and upload are separate API calls. The API offers no conditional-create
guarantee here, so concurrent writers can race after an empty lookup; coordinate
publishers for the same tenant. This module never deliberately sends an update
for an observed rule. Newly uploaded rules apply according to XDR's IOC policy;
the documented endpoint does not scan historical data. This action does not
isolate endpoints or invoke a file block-list API.

## Failures and request bounds

The result contains `uploaded`, `existing`, `planned`, `failed`, `not_attempted`,
`skipped` and per-indicator outcomes. API lookup errors, malformed acknowledgements
and validation failures make `success=false` and add a top-level module error.
Processing stops after the first failed/uncertain API operation; remaining
indicators are `not_attempted`. Earlier confirmed uploads remain reported.
Timeouts or lost acknowledgements can leave remote state uncertain; inspect the
tenant before retrying. Uploads are never automatically retried.

The action has a 120-second budget checked before each indicator and again
after preflight, before starting an upload. Individual
requests use 20-second connect/read timeouts, so a current request can finish
after the budget. Empty/no-eligible selections are explicit no-ops. Standard
and Advanced authentication follow the same public API contract as the lookup
module. Advanced requests use fresh nonces/timestamps; explicit auth prevents
`.netrc` substitution. TLS verification and inherited proxy/CA settings are
preserved. Redirects are rejected, response bodies are capped at 2 MiB and
sessions/responses are closed. Errors omit provider bodies and credentials.
The server's opt-in HTTP tracing logs headers and bodies, including API keys.

## Example

POST to the module server's `/query` endpoint to preview:

```json
{
  "module": "cortex_xdr_ioc_publish",
  "params": {"source": "MISP production", "dry_run": "true"},
  "data": {
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
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

## Validation and references

Tests exercise the real prepared HTTP requests with synthetic replies. They
cover both authentication modes, preview without credentials, source selection,
normalization, provenance, exact existing-rule checks, expiry, single-IOC upload
acknowledgements, partial failures, limits and workflow discovery/query endpoints.
No live tenant was available and no live IOC rules were changed during testing.

- [Authentication](https://cortex-docs.paloaltonetworks.com/xdr-api/make-your-first-api-call)
- [IOC lookup](https://cortex-docs.paloaltonetworks.com/xdr-api/cortex-platform/iocs)
- [Simple indicator JSON upload](https://cortex-docs.paloaltonetworks.com/xdr-api/cortex-platform/indicator-rules)

- [Native IOC types and Pro license](https://cortex-docs.paloaltonetworks.com/cortex-xdr/detect-investigate-and-respond-to-threats/threat-management/detection-rules/whats-an-ioc/create-an-ioc-rule)
