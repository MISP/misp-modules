# OSQuery Pack Publish

This workflow action publishes a local JSON query pack using the same builder
as [OSQuery Export](../export_mod/osqueryexport.md). It supports native osquery
filesystem deployments and existing configuration-distribution pipelines.
It does not execute queries, reload daemons, distribute files to remote hosts,
or implement a Fleet/Kolide management API.

## Server setup

Create a dedicated pack directory on the **module server**, owned by the service
account and writable only by trusted administrators and that account. Set
`OSQUERY_PACK_DIRECTORY` to its absolute path in the module service environment.
The request cannot choose the output directory. The directory must already
exist. Files are written with mode `0640`; arrange group access for your reader
or distribution service. The action requires a POSIX module server with atomic
hard-link creation and rename support on the target filesystem; generated packs
can target Windows, Linux or macOS.

Example main configuration on an osquery host after distributing the file:

```json
{"packs": {"misp-example": "/etc/osquery/packs/misp-example.conf"}}
```

The pack must be referenced by a configuration plugin, distributed to the right
hosts and loaded through your normal configuration reload procedure. A successful
publication confirms the local write; it does not confirm endpoint activation
or detections. Do not point this action at the main `osquery.conf` directory
expecting a bare query pack to act as a complete daemon configuration.
For glob-based pack discovery, match `misp-*.conf` so temporary publication files
are excluded.

## Workflow request

```json
{
  "module": "osquery_pack_publish",
  "params": {
    "pack_name": "example",
    "interval": "3600",
    "scan_path": "/tmp/%%",
    "dry_run": "true",
    "overwrite": "false"
  },
  "data": [{"Event": {"Attribute": [
    {"type": "ip-dst", "value": "192.0.2.1", "to_ids": true}
  ]}}]
}
```

`pack_name` is required: 1–64 letters, digits, underscores or hyphens, starting
with a letter or digit. The output basename is `misp-<pack_name>.conf`.
`interval` and `scan_path` have the same meaning as in the export. Only
IDS-marked attributes are eligible. Deleted events, objects and attributes are
excluded. Workflow filters and extracted `matchingData` are unsupported and
rejected; pass the intended selected events in `data`.

`dry_run` defaults to `true` and needs no server directory. Inspect the returned
`data.pack`, `data.summary` and provenance before setting `dry_run=false`.
The response uses `result_key: osquery_pack_publish` and includes the filename,
content SHA-256 and a `planned` or `published` status.

Publication creates the complete file atomically. It refuses existing files
unless `overwrite=true`, and refuses symlink targets. Overwrite replaces the
**whole named pack** with queries from the supplied snapshot; it does not merge
events with earlier runs. For independent event workflows use distinct pack
names, or supply the full desired event collection on every update. Empty packs
are rejected to prevent accidental clearing. Removal and expiration require the
operator's normal pack lifecycle; the action never deletes packs automatically.

Native osquery's [remote interface](https://github.com/osquery/osquery/blob/5.24.0/docs/wiki/deployment/remote.md)
has clients pull configuration or distributed queries. A generic HTTP POST to an
osquery agent would not publish a pack. This local action deliberately uses the
documented [filesystem pack contract](https://github.com/osquery/osquery/blob/5.24.0/docs/wiki/deployment/configuration.md#query-packs).
