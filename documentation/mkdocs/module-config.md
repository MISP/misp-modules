# Local module configuration defaults

MISP normally sends each module's configuration, such as API keys and service
URLs, in the `config` object of a `/query` request. You can optionally keep
defaults in a single JSON file on the host running misp-modules. API settings
take precedence, and local defaults fill missing settings before the module runs.

This feature is disabled unless you start the service with `--module-config`.
Existing installations and API clients need no changes. Local configuration does
not enable modules in MISP, install optional dependencies, or change organisation
restrictions. Continue to enable and restrict modules in MISP as usual.

## Create the configuration file

Create `/etc/misp-modules/modules.json` with the following structure, replacing
the example credentials and URL:

```json
{
  "version": 1,
  "modules": {
    "shodan": {
      "config": {
        "apikey": "REPLACE_WITH_SHODAN_KEY"
      },
      "fallback_when_empty": ["apikey"]
    },
    "cuckoo_submit": {
      "config": {
        "api_url": "https://sandbox.example.org",
        "api_key": "REPLACE_WITH_CUCKOO_KEY"
      },
      "fallback_when_empty": ["api_url", "api_key"]
    }
  }
}
```

Use the module's API identifier (the `name` returned by `GET /modules`), rather
than its display name. Configuration names must match the module's existing keys:
for example, Shodan uses `apikey`, while Cuckoo Submit uses `api_key` and
`api_url`. Available keys are listed in each module's documentation and in
`meta.config` from `GET /modules`.

The top-level fields are `version` (currently the integer `1`) and `modules`.
Each module entry requires a `config` object and optionally a
`fallback_when_empty` list. Every key in that list must also exist in the entry's
`config`. Unknown structural fields and invalid field types cause a startup
error. Module names and configuration keys must be nonempty; names beginning
with the dispatcher's reserved `type:` prefix are not allowed.

Configuration values retain their JSON types. Use strings, booleans, numbers,
lists, or objects as expected by the module. Values are not coerced, expanded from
environment variables, or merged recursively. A nested API value replaces the
whole corresponding local value.

Entries for modules that are not installed are allowed and have no effect until
those modules are available. The service does not validate configuration keys
against module metadata; check the spelling and the module's requirements.
Custom modules loaded with `--custom` use the same lookup and precedence rules.

## Start the service

```bash
misp-modules --module-config /etc/misp-modules/modules.json
```

The service reads and validates the file once, before loading modules or
listening for requests. If the file cannot be read, contains invalid JSON, or
does not follow the structure above, startup stops with an error. Error messages
do not print configuration values.

Restart misp-modules after editing the file or rotating a credential. There is
no automatic reload and no API endpoint to read or modify this file. Remove the
`--module-config` option and restart to return to API-only configuration.

### Running with systemd

For an existing service, use `sudo systemctl edit misp-modules` to add an override
like this. Replace the executable path and retain your existing startup options:

```ini
[Service]
ExecStart=
ExecStart=/path/to/venv/bin/misp-modules -l 127.0.0.1 --module-config /etc/misp-modules/modules.json
```

Then apply the override:

```bash
sudo systemctl daemon-reload
sudo systemctl restart misp-modules
sudo systemctl status misp-modules
```

If you run misp-modules in a container, mount the file read-only and pass its
path inside the container to `--module-config`.

## Precedence and empty values

Defaults are applied independently for each key in the selected module's
`config`. Other request fields, including attributes, data, and the top-level
request timeout, are unaffected.

| API setting | Effective setting |
| --- | --- |
| Key omitted, or the entire `config` field omitted | Local default, if present |
| Explicit nonempty value | API value |
| `false`, `0`, an empty list, or an empty object | API value |
| `""` or `null` | API value, unless the key is in `fallback_when_empty` |
| `""` or `null` for a key in `fallback_when_empty` | Local default |
| No API value and no local default | Existing module behavior |

`fallback_when_empty` defaults to an empty list. Add credential or URL keys to
it if your MISP instance sends `""` or `null` for settings left unconfigured.
Whitespace-only strings are explicit values and are not considered empty.
To preserve an intentional empty string or null for a particular key, remove
that key from `fallback_when_empty`.

For example, using the Cuckoo defaults above, this request configuration:

```json
{
  "api_url": "https://another-sandbox.example.org",
  "api_key": ""
}
```

reaches the module with `https://another-sandbox.example.org` as its URL and the
local Cuckoo API key. A nonempty API key in the request would take precedence.

The `config` field, when supplied, must still be a JSON object. Malformed API
values such as `"config": null`, strings, or lists are passed to the existing
handler unchanged; local defaults do not repair malformed requests.

Fallback happens before execution. If an API-supplied credential is invalid,
the module reports its normal error; the service does not retry with local
credentials. Both dictionary handlers and legacy JSON handlers receive the
same effective configuration. Direct Python calls to individual module handlers
bypass the service dispatcher and therefore do not apply these defaults.

## Protect credentials

Keep the file outside the source checkout and restrict access to the service
account. For example, if the service runs as `misp`:

```bash
sudo chown misp:misp /etc/misp-modules/modules.json
sudo chmod 0600 /etc/misp-modules/modules.json
```

Ensure that account can also traverse the containing directory. Use your actual
service user, such as `apache`, if different. Do not commit real credentials.

Local defaults are not added to `/modules`, `/openapi.json`, or `/statistics`.
The dispatcher's debug request log records the original API payload before local
defaults are added. API-supplied credentials can still appear in that existing
log. Individual modules may log or return their configuration, and
`--debug-extended` deliberately logs outbound HTTP credentials and bodies;
protect those logs and enable extended debugging only when needed.

Any caller able to query a module on this service can use its local credentials.
Keep access to misp-modules restricted. If several MISP instances share one
service, they also share its local defaults; run separate services when different
credentials or trust boundaries are required.
