# Optional PAP:RED expansion restrictions

Start misp-modules with the global `--restrict-pap-red` option to check PAP:RED
markings before running an expansion module:

```bash
misp-modules --restrict-pap-red
```

The option is **disabled by default**. Without it, requests reach the existing
handlers unchanged, including requests containing PAP:RED tags. It can be combined
with `--module-config` and other existing startup options. For systemd, add it to
the service's `ExecStart` command and restart the service. Remove it and restart
to restore the default behavior.

## Behavior when enabled

| Request | Result |
| --- | --- |
| No supplied PAP:RED marking | Existing behavior |
| PAP:RED hover | Blocked for all sources |
| PAP:RED manual expansion, explicitly internal module | Allowed |
| PAP:RED manual expansion, external or unclassified module | Blocked |
| Import, export or action module | Existing behavior |

Rejection happens before local configuration defaults are resolved or either
the dictionary or legacy JSON handler is called. The response uses the existing
HTTP 200 module-error format, for example:

```json
{"error": "External expansion blocked by the PAP:RED policy."}
```

Blocked requests count as `module_errors` in `/statistics`. They produce no
expansion results. This option does not change enforcement of other PAP levels,
TLP markings, import, export or action modules.

## Supplying markings and hover context

**The caller must forward effective attribute, object and event markings.**
The service does not have a MISP database connection and cannot infer parent
tags from a bare value, attribute UUID or event ID.

For both simplified and MISP-standard requests, callers can put the union of
applicable tags in a top-level `tags` array. Set `hover` to the JSON boolean
`true` for automatic hover requests, including persistent hover expansions:

```json
{
  "module": "dns",
  "attribute": {
    "type": "domain",
    "value": "example.org",
    "uuid": "13d8d18b-784a-42a0-9a58-a9cddbfda561"
  },
  "tags": ["PAP:RED"],
  "hover": true
}
```

Tags can also be supplied as `{"name": "PAP:RED"}` objects, or in MISP `Tag`,
`AttributeTag`, `ObjectTag` and `EventTag` structures. The policy checks supplied
`attribute`/`Attribute`, `object`/`Object` and `event`/`Event` containers, including
nested attributes and objects. A red marking at any supplied level takes
precedence over other tags. Tag matching is case-insensitive; TLP:RED and text
that merely mentions PAP:RED are not PAP markings.

For a module advertising only `hover`, requests are always treated as hover.
Modules advertising both `hover` and `expansion` require the caller's `hover`
flag to distinguish automatic requests from manual expansion.

### MISP integration limitation

Existing MISP clients can omit tags and the hover indicator, especially on the
simplified hover path. Enabling this option alone cannot protect intelligence
whose markings are omitted. Such requests keep their existing behavior. Before
relying on this restriction, ensure the calling MISP version or integration
forwards all applicable parent markings and identifies hover requests as above.
This PR provides the module-server policy and request contract; corresponding
MISP-side forwarding is needed for complete coverage of issue
[#576](https://github.com/MISP/misp-modules/issues/576).

Direct Python calls to individual module handlers bypass this service policy.

## Declaring internal and external sources

Module authors can add `data-source` to the metadata returned by `version()`:

```python
moduleinfo = {
    "module-type": ["expansion", "hover"],
    "data-source": "internal",
    # Other module metadata...
}
```

Use `internal` only for passive processing that cannot expose supplied
intelligence outside the trusted environment, such as local syntax validation
or passive queries against internal logs. Use `external` for public API lookups,
DNS resolution, submissions and other externally observable activity. An internal
hostname alone does not guarantee that a service never forwards data outside.

The Sigma syntax validator declares an internal source; the DNS resolver declares
an external source. Other modules can adopt the field incrementally. Missing,
invalid or unrecognised values are treated as external when the option is enabled.
No existing module needs to change for default operation.

The declaration is visible as `meta.data-source` in `/modules` and its generated
OpenAPI examples. It is trusted module metadata, not a per-request setting:
supplying `data-source` or disabling the policy in request `config` cannot grant
an exception. Custom modules use the same rules. For deployment-specific internal
services, audit their behavior before declaring them internal in the module.
