# OSQuery Export

Reviewed against [osquery 5.24.0](https://github.com/osquery/osquery/releases/tag/5.24.0),
the latest stable release returned by the upstream release API on 25 October 2026.
The module generates queries; exporting does not contact or execute anything on endpoints.

## Compatibility findings and migration

Version 1.1 wrote SQL statements to a `.conf` download. Those statements could be
used individually in a query tool, but were not an osquery configuration or pack.
Version 2.0 defaults to a JSON query pack containing `queries`, stable query names,
integer `interval` values and per-query `platform` selectors. Reference this pack
from an osquery configuration; do not use it as the entire main configuration.
Set `config.format` to `sql` to retain raw SQL output, and save that download as
`.sql`. The download metadata describes the default JSON `.conf` output.

Other corrections:

| Previous behavior | Current behavior |
| --- | --- |
| Service-name lookup used nonexistent `services.service_name` | Uses `services.name`; display names use `display_name` |
| All comparisons used unescaped `LIKE` values | SQL quotes are escaped; indicators match literal values, including `%` and `_`; DNS names match case-insensitively |
| `regkey` queried a registry value's `path` | Queries the registry `key`; HKCU maps to user hives, aliases expand only at the root |
| Composite registry values split at every `\|` | Splits once, preserving pipes in data |
| Mutex query matched other named object types | Requires `object_type = 'Mutant'` |
| Unbounded file hashing and YARA scan, hash result limited to one | Requires a scan path, constrains both joins by file path, returns all matches |
| YARA used the `yara` alias | Uses current `yara_file`, with a 5.24.0 minimum selector; `yara` is still an upstream alias |
| Windows queries ran on every platform | Windows registry, services, tasks, pipes, mutex and DNS cache queries carry `platform: windows` |
| Only top-level attributes were exported | Includes object attributes; wrapped, bare and legacy event layouts are accepted |

## Request

```json
{
  "module": "osqueryexport",
  "config": {"format": "pack", "interval": "3600", "scan_path": "/tmp/%%"},
  "data": [{"Event": {"Attribute": [
    {"type": "ip-dst", "value": "192.0.2.1", "to_ids": true},
    {"type": "windows-service-name", "value": "BadService", "to_ids": true}
  ]}}]
}
```

The response's base64 `data` decodes to a pack. `summary`, `warnings` and
`sources` stay outside the file, preserving the osquery schema. Duplicate queries
are combined and their event, object and attribute references retained.

| Setting | Default | Meaning |
| --- | --- | --- |
| `format` | `pack` | JSON query pack, or `sql` for raw statements |
| `interval` | `3600` | Integer seconds, 1–604800 |
| `scan_path` | empty | Absolute osquery file path pattern, e.g. `/tmp/%%` or `C:\Temp\%%` |
| `include_non_ids` | `false` | Include attributes not marked `to_ids`; deleted data remains excluded |

Supported types: `regkey`, `regkey|value`, `mutex`,
`windows-service-displayname`, `windows-service-name`, `windows-scheduled-task`,
`named pipe`, `domain`, `ip-src`, `ip-dst`, `filename`, `sha256`, `yara`.
Malformed or unsupported attributes are skipped with counts. Invalid request
structure or settings return an error. Packs are limited to 1000 unique queries.

An absolute filename searches that exact path. A bare filename, SHA-256 or YARA
rule requires `scan_path`; without one it is skipped with a warning. Paths use
[osquery wildcard syntax](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/):
`%` matches one level and `%%` recurses. The operator controls scan breadth and
must choose paths appropriate to the target hosts. File queries select POSIX or
Windows based on the path. YARA checks regular files smaller than 8 MB; inline
rules are embedded in the pack. Rule compilation depends on the target build's
YARA support. `ip-src` checks local socket addresses, `ip-dst` remote addresses;
DNS checks the Windows DNS cache using case-insensitive whole-name comparisons,
not historical DNS or network traffic.

## Deployment

Save decoded JSON as `/etc/osquery/packs/misp-indicators.conf`, then include it in
your existing main configuration:

```json
{"packs": {"misp-indicators": "/etc/osquery/packs/misp-indicators.conf"}}
```

Validate with `osqueryi --config_check --config_path=/etc/osquery/osquery.conf`.
Distribute the pack to the intended hosts and reload their configuration using
your deployment's normal procedure. Query intervals default to one hour and
removed-row logging is disabled. Test scan cost on representative hosts first.

The [OSQuery Pack Publish action](../action_mod/osquery_pack_publish.md) automates
writing the pack on the module server. Fleet, Kolide and other management APIs
require their own transport adapter; native osquery pulls configuration from a
plugin and has no generic server-side push endpoint for this action to call.

## Verification sources and limits

The tests compile every generated SQL shape against columns captured from the
[5.24.0 table specifications](https://github.com/osquery/osquery/tree/5.24.0/specs).
Optional integration tests use the real `osqueryi` binary for exact file lookup,
basename lookup, SHA-256 matches, inline YARA matches and configuration parsing:

```sh
OSQUERYI=/path/to/osqueryi poetry run pytest -q tests/test_osquery.py
```

Windows SQL and platform metadata are tested against the schema and SQLite;
Windows API behavior requires verification on a Windows endpoint.
See upstream [configuration](https://github.com/osquery/osquery/blob/5.24.0/docs/wiki/deployment/configuration.md)
and [YARA](https://github.com/osquery/osquery/blob/5.24.0/docs/wiki/deployment/yara.md)
documentation for the pack and scan contracts.
