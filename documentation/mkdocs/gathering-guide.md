# Gathering modules

Gathering modules collect source data into a complete standard MISP feed directory,
ZIP that directory and return the archive through a streaming endpoint. Source
conversion stays in the producer; MISP keeps its existing event importer and
UUID/timestamp deduplication. No consumer import state is stored by the module.

## Version 2: background generation and binary download

`GET /modules` advertises `type: gathering`, `meta.module-type: [gathering]`,
`mispattributes.gathering_version: 2` and a module-specific parameter schema.
Start generation through the ordinary module interface:

```json
{"module":"withaname","operation":"prepare","parameters":{"date_from":"2023-06-24","date_to":"2023-06-25","deduplicate_entries":true},"config":{}}
```

`POST /query` returns promptly with a small job descriptor:

```json
{"gathering_version":2,"source_format":"misp","job_id":"<64 lowercase hex characters>","module":"withaname","status":"queued","created_at":1790856000}
```

Poll `GET /gathering/jobs/<job_id>` until `status` is `ready` or `failed`.
Ready status adds `event_count`, `archive_size`, `sha256` and `expires_at`.
Download `GET /gathering/jobs/<job_id>/feed.zip` directly to a local file; this
returns binary `application/zip` in 64 KiB chunks with backpressure. It does not
return base64 data or a JSON array of events. No caller-provided download URL
is used. The random job ID is a capability: keep it within the trusted MISP/module
service connection, just like the other module APIs.

The ZIP contains flat, ordinary feed files:

```text
manifest.json
<event-uuid>.json
<event-uuid>.json
...
```

Every event uses the standard `{"Event": {...}}` wrapper. The complete manifest
and archive are published only after generation finishes; failed jobs expose no
archive. `DELETE /gathering/jobs/<job_id>` releases ready artifacts or requests
cooperative cancellation of queued/running generation. Clients should release
artifacts in a finally block. Unclaimed terminal jobs expire after the configured
retention period and are reaped periodically by the module service.

This replaces the unmerged version 1 in-memory bundle proposal. The former
100-event / 32 MiB bundle restrictions no longer apply. `hashes.csv` generation,
daily aggregation and protected-event signatures remain outside this first
producer's scope.

## Local origin tags

Every event created by a gathering producer includes two default event-level
tags from the `misp-gathering` taxonomy:

| Producer | Module tag | Source tag |
| --- | --- | --- |
| WithAName | `misp-gathering:module="withaname"` | `misp-gathering:source="witha.name"` |
| BeaconBeagle (all datasets) | `misp-gathering:module="beaconbeagle_gathering"` | `misp-gathering:source="beaconbeagle.com"` |

`module` identifies the collector by its `/modules` identifier; `source`
identifies the upstream provider by its canonical domain. Add values to the
taxonomy when introducing a producer. These tags describe collection provenance,
not confidence, review status or ownership of the observed infrastructure.

Tags are included in both the event JSON and `manifest.json`, using the standard
MISP representation, for example:

```json
{"name":"misp-gathering:module=\"withaname\"","local":true}
```

MISP's event importer preserves `local` on the event/tag association. Local tags
remain visible and filterable on that instance and are excluded from ordinary
outgoing synchronisation; internal sync can include them. The taxonomy defines
the vocabulary; locality is set explicitly in each generated tag. Enable the
taxonomy to make its descriptions available in the tag picker. Creating an
unknown tag on import remains subject to the importing user's MISP permissions.

The tags are deterministic and do not alter event, object or attribute UUIDs.
Adding them to previously generated events advances their revision through the
existing revision store; repeated collection then keeps that revision. Preserve
the revision store when upgrading so previously imported events can receive the
tags on their next update.

## Repeat imports and corrections

Every gathering producer supplies UUIDv5 identifiers for the event, its objects,
its attributes and each object's attributes. Use `stable_uuid(namespace, *keys)`
from `misp_modules.lib.gathering` with a fixed source namespace and a stable
upstream record key. Scope each child to its parent. For example, a new producer
could use the following keys for a source link:

```python
source_namespace = stable_uuid(NAMESPACE, "example.org/feed")
event_uuid = stable_uuid(source_namespace, record["id"])
link_uuid = stable_uuid(event_uuid, "link", record["url"])
```

Choose keys that represent the intended identity across corrections. Both
existing producers identify their raw attachment independently of its bytes,
so replacing the attachment content updates the same MISP attribute. Preserve
published namespaces and key formats when updating a producer.

`FeedBuilder.add()` verifies the UUID version at every level. It writes one
copy of identical entries with the same UUID, including repeated events in a
job. Conflicting content for one UUID within a single event or two versions of
the same event within one feed fail generation. Objects and attributes are
ordered by UUID. Tags are ordered by content. Producers still normalize their
source-specific unordered collections, including those in JSON attachments.

The first event revision uses the supplied source timestamp. Repeating a
collection preserves the event and manifest timestamps and the timestamp on
each object and attribute. A correction advances the event revision and assigns
it to new or changed items and their containing objects. Unchanged siblings keep
their timestamps. Source observation fields such as `first_seen` and `last_seen`
participate in change detection. The builder supplies MISP revision timestamps.

Keep the existing SQLite revision index when upgrading. For a previously
gathered event whose content still matches the stored digest, the first run
preserves its last emitted timestamp for every item. If the source has already
changed, the first run assigns the new event revision to its children because
the old index recorded only the whole-event digest. Subsequent runs track each
child independently.

## Memory and disk use

`FeedBuilder(directory)` writes each complete event to its own JSON file as it
arrives. A temporary SQLite manifest index is streamed into `manifest.json` at
completion. ZIP creation reads those files in 64 KiB chunks; the full feed and
archive are never assembled in memory. The temporary feed directory and index
are deleted after the ZIP is ready. Peak event-content memory is proportional
to the largest event, with additional source-listing and ZIP central-directory
metadata proportional to the number of files. A single unusually large event
still needs to fit in the producer and MISP importer memory budgets.

Allow disk space for the uncompressed feed plus its ZIP during finalization.
Operator budgets fail a generation explicitly; they never silently truncate it:

| Environment variable | Default |
| --- | --- |
| `MISP_MODULES_GATHERING_STATE_DIR` | Service-UID directory under the system temporary directory; set a durable directory in production. |
| `MISP_MODULES_GATHERING_WORKERS` | 2 background generation workers per service process. |
| `MISP_MODULES_GATHERING_QUEUE` | 8 additional queued jobs per service process. |
| `MISP_MODULES_GATHERING_TIMEOUT` | 86400 seconds; producers must check cooperative cancellation. |
| `MISP_MODULES_GATHERING_RETENTION` | 86400 seconds after success/failure. |
| `MISP_MODULES_GATHERING_MAX_BYTES` | 10 GiB of event JSON per generation. |
| `MISP_MODULES_GATHERING_MAX_EVENT_BYTES` | 256 MiB per event JSON. |

Generation runs outside the `/query` HTTP request timeout. Ready artifacts and
job status survive a service restart when storage is durable. A generation whose
owning process died is marked failed, identified using PID and process start time;
its partial files are removed and the consumer can submit again. Jobs do not
resume halfway through a source after restart. Long sources use finite network
timeouts and `builder.check_cancel()` between requests/chunks. Cancellation is
cooperative, so producers must implement those checks. Queue capacity is bounded.

## WithAName

The producer reads only `https://witha.name/data/` and recognized timestamped
configuration filenames. It never contacts the systems listed in the dataset,
and source requests do not follow redirects. Each source file has an 8 MiB limit;
the whole collection no longer has a 120-second / 16 MiB download limit.

| Parameter | Meaning |
| --- | --- |
| `date_from` | Inclusive UTC observation date; defaults to yesterday. |
| `date_to` | Exclusive UTC observation date; defaults to tomorrow. |
| `max_events` | Optional non-negative count budget. Default 0 collects every matching snapshot. Exceeding a positive budget fails. |
| `deduplicate_entries` | Boolean, default true; collapse identical rules within a configuration. |

One snapshot becomes one event; each target rule becomes a `ddos-config` object.
Filename timestamps are interpreted as UTC. Rules for the same hostname remain
separate when their meaning differs. Source fields with underscores map to the
corresponding hyphenated relations; bodies and headers use canonical JSON text.
Random placeholders remain literal. A canonical JSON attachment preserves the
configuration, including `randoms` and unmapped fields. Array ordering of targets
and random definitions is normalized for reproducibility.

Listed systems are victim targets: all generated attributes disable IDS export
and correlation. UUIDv5 identifiers are stable and scoped to the source, event,
rule and attribute. Switching entry deduplication selects a separate view identity;
date windows only select complete events. Content changes keep the event UUID
and advance its timestamp through the shared revision index. A changed rule has
a new object UUID; no deletion tombstones are emitted, so normal MISP merge
semantics can retain previous rule versions after a historical correction.

## BeaconBeagle

The `beaconbeagle_gathering` producer gathers decoded Cobalt Strike configurations, beacon
hosts and C2 infrastructure from the public BeaconBeagle API. Select `dataset`
(`all`, `configs`, `beacons` or `c2`), optional last-observation UTC dates,
`page_size` and an optional `max_events` budget. See the
[BeaconBeagle usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/gathering/beaconbeagle.md)
for requests, conversion details and source limitations.

## Durable revisions and additional producers

Preserve the SQLite revision index in `MISP_MODULES_GATHERING_STATE_DIR` across
upgrades. All workers/replicas serving the same feed need the same conversion
version and shared storage suitable for SQLite locking, or one designated
producer. Losing the index can prevent a historical correction from receiving a
newer revision than an already imported copy. Credentials and request parameters
are not written to job status files; normal module config/defaults are available
to the background producer in memory.

To add another source:

1. Add a module under `misp_modules/modules/gathering/` with normal metadata and
   introspection, advertising contract version 2 and its parameter schema.
2. Validate parameters, then call `get_jobs().submit(name, parameters, config,
   producer)` from its handler. Return that small descriptor to `/query`.
3. Implement `producer(parameters, builder, config)`, calling
   `builder.add(event, source_timestamp)` once per complete event and checking
   cancellation during slow work. The framework builds the manifest and ZIP.
4. Add `origin_tags(module_identifier, source_domain)` from
   `misp_modules.lib.gathering` to the event's `Tag` list before `builder.add()`.
   Keep this in the gathering producer when sharing a converter with expansion.
5. Follow the [repeat import rules](#repeat-imports-and-corrections) for UUID
   keys and source timestamps. Scope content-filtered views and exclude volatile
   retrieval metadata.
6. Test reordered data, retries, corrections, limits and job lifecycle. The MISP
   integration discovers producers without a source-specific allowlist.
