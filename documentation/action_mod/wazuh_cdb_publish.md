# Wazuh CDB publish

`wazuh_cdb_publish` uploads a typed snapshot of IDS-marked MISP event and object
indicators to the Wazuh **server API**, normally on HTTPS port 55000. It uses
`PUT /lists/files/{filename}` with `Content-Type: application/octet-stream` and the
same source-list content as [Wazuh CDB Export](../export_mod/wazuh_cdb_export.md).
It does not use the Wazuh indexer API.

## Module server configuration

Set these environment variables on the misp-modules server:

| Variable | Purpose |
| --- | --- |
| `WAZUH_URL` | HTTPS API origin, for example `https://wazuh.example:55000` |
| `WAZUH_USERNAME`, `WAZUH_PASSWORD` | Wazuh API user credentials |
| `WAZUH_API_TOKEN` | Optional existing JWT; takes precedence over username/password |
| `WAZUH_CA_BUNDLE` | Optional path to a trusted CA PEM bundle for an internal CA |

With username/password, each live invocation obtains a JWT using
`POST /security/user/authenticate?raw=true`. An existing JWT must be refreshed
outside the module when it expires. Credentials are never stored in workflow
parameters or returned in results. TLS verification stays enabled, redirects are
disabled, requests use a 5-second connection and 30-second read timeout, and
failed requests are not retried automatically.

Use a dedicated Wazuh API account with the `lists:update` and `lists:delete`
permissions required by the upload endpoint. Check the RBAC requirements for
your Wazuh version. The implementation follows the Wazuh 4.14.1 API specification.

## Workflow parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `filename` | Required | Dedicated list basename, for example `misp-ipv4`; 1–128 letters, digits, underscores or hyphens, starting with a letter or digit |
| `indicator_type` | `ipv4` | `ipv4`, `ipv6`, `domain`, `md5`, `sha1`, `sha256` or `sha512` |
| `overwrite` | `false` | `true` replaces the **entire file** with the supplied snapshot |
| `dry_run` | `false` | `true` returns the planned source text without credentials or network access |

Use one dedicated file per indicator type and publisher. With `overwrite=false`,
an existing filename causes a failure instead of being modified. With
`overwrite=true`, supply the complete intended list: the action does not merge
remote entries, and per-event workflows would replace the previous event's list.
It does not automatically retrieve other MISP events. Concurrent publishers to
the same file are not supported; serialize updates.

The module accepts selected event(s) in workflow `data`, including object attributes,
in standard, bare or legacy format. Only `to_ids` attributes are eligible; deleted
data is excluded. Workflow filters and extracted data are unsupported and rejected
to avoid uploading an unintended snapshot. The action refuses empty or oversized
lists. See the export guide for normalization, supported composite types and limits.
Skipped attributes are counted and reported in warnings; review the dry run before
replacing a list.

## Example dry run

POST this JSON to the module server's `/query` endpoint:

```json
{
  "module": "wazuh_cdb_publish",
  "params": {
    "filename": "misp-ipv4",
    "indicator_type": "ipv4",
    "overwrite": "false",
    "dry_run": "true"
  },
  "data": [{"Event": {"uuid": "event-1", "Attribute": [
    {"type": "ip-dst", "value": "192.0.2.1", "to_ids": true, "uuid": "attribute-1"}
  ]}}]
}
```

The result uses `result_key="wazuh_cdb_publish"`. Its `data` includes:

- `success`, `status` (`planned`, `uploaded`, `not_uploaded` or `unknown`), and the selected filename;
- indicator count, skipped counts, file byte length and content SHA-256;
- `activation="pending"`, since upload does not load detection rules;
- the exact `content` for dry runs only.

Set `dry_run=false` to upload. Success requires HTTP 200, Wazuh `error=0`, zero
failed items, and acknowledgement of exactly `etc/lists/{filename}`. Wazuh errors
inside HTTP 200 responses are failures. Timeouts, HTTP failures or invalid
acknowledgements during upload produce an error and an uncertain outcome; inspect
Wazuh before retrying. There is one file upload per invocation, with no batching.

## Activation

Register the list in `ossec.conf`, reference it in a detection rule, and restart
the Wazuh manager using your deployment's normal procedure. The action leaves
activation pending and does not modify configuration, trigger Active Response,
delete lists or restart services. See the
[export guide's configuration and rule example](../export_mod/wazuh_cdb_export.md#activate-the-list-in-wazuh).

No new MISP object template is required; existing attributes and objects supply
the indicators.

References:

- [Wazuh server API](https://documentation.wazuh.com/current/user-manual/api/index.html)
- [Wazuh API Lists reference](https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Lists)
- [Wazuh 4.14.1 API specification](https://github.com/wazuh/wazuh/blob/v4.14.1/api/api/spec/spec.yaml)
