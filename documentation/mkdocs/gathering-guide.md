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
| Offensive Agency | `misp-gathering:module="offensive_agency"` | `misp-gathering:source="offensive.agency"` |

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

The tags use stable values across collections. Existing MISP events receive
updated tags when the feed supplies a newer event revision.

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

Standard gathering jobs use the producer's UTC source timestamp (Unix seconds)
for the event, its publish timestamp, the manifest, and every object and
attribute. Supply a time intrinsic to the source record, such as its upstream
modification time or snapshot date. Replicas running the same converter on
the same source data generate identical records and revisions, even with
different local histories and clocks. The service ignores old
`revisions.sqlite3` files.

MISP looks up the event by UUID. It adds a new UUID and schedules an existing
event for editing only when the incoming timestamp exceeds the stored one.
An exact repeat is skipped. A source correction with the same timestamp is
also skipped. After upgrading from a stateful producer, an already-imported
event can have a locally generated revision ahead of its source time. The
next source revision must exceed that stored timestamp for MISP to update it.
[MISP feed import logic](https://github.com/MISP/MISP/blob/2d7de9643b9677231faf5660d8eca1cc9a090be2/app/Model/Feed.php#L260-L278)

## Memory and disk use

`FeedBuilder(directory)` writes each complete event to its own JSON file as it
arrives. Each job keeps a temporary SQLite index to check UUID uniqueness and
stream `manifest.json` at completion. ZIP creation reads the event files in
64 KiB chunks. The temporary feed directory and index
are deleted after the ZIP is ready. Peak event-content memory is proportional
to the largest event, with additional source-listing and ZIP central-directory
metadata proportional to the number of files. A single unusually large event
still needs to fit in the producer and MISP importer memory budgets.

Allow disk space for the uncompressed feed plus its ZIP during finalization.
Operator budgets fail a generation explicitly; they never silently truncate it:

| Environment variable | Default |
| --- | --- |
| `MISP_MODULES_GATHERING_STATE_DIR` | Service-UID directory under the system temporary directory. Stores job status and ZIP artifacts. Set a durable directory to retain them across restarts. |
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
date windows only select complete events. The snapshot filename fixes its event
UUID and timestamp for a given view. Rewriting a file under the same name
keeps the same event revision. MISP skips that revision on repeat import.

## BeaconBeagle

The `beaconbeagle_gathering` producer gathers decoded Cobalt Strike configurations, beacon
hosts and C2 infrastructure from the public BeaconBeagle API. Select `dataset`
(`all`, `configs`, `beacons` or `c2`), optional last-observation UTC dates,
`page_size` and an optional `max_events` budget. See the
[BeaconBeagle usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/gathering/beaconbeagle.md)
for requests, conversion details and source limitations.

## Offensive Agency

`offensive_agency` collects the tracker's public ONYPHE-based observations.
With empty parameters it creates one event for the published report date,
including headline counts and an aggregate JSON attachment with the per-agent
breakdowns and time series. The source's reporting date supplies the event
timestamp at midnight UTC. Corrections to the same report keep its UUID.

```json
{"module":"offensive_agency","operation":"prepare","parameters":{}}
```

To monitor your inventory, supply individual IPv4 or IPv6 addresses in
`asset_ips`. The module sends each distinct address to Offensive Agency's
per-host API and emits one event for each match. An HTTP 404 means the
tracker has no record. Other HTTP errors fail the job.

```json
{"module":"offensive_agency","operation":"prepare","parameters":{"asset_ips":["192.0.2.1","2001:db8::1"]}}
```

Asset events include the first and last observation dates, network context,
agent names, and the provider's confirmed or probable classification.
An observation describes software exposure. Operator intent is unknown.
IP attributes use UTC day precision. Shared CDN addresses have correlation
disabled. For cloud IPs, compare the observation dates with your log dates.
All attributes have IDS export disabled. The module requires no API key and
makes requests only to the provider. [Source methodology and exports](https://offensive.agency/about)

## Durable revisions and additional producers

A custom caller can explicitly pass
`FeedBuilder(directory, revisions=RevisionStore(path))` when it needs to
publish corrections whose upstream timestamp stays fixed. This opts into
history-dependent, per-item revisions. Such callers need a common revision
store to agree across instances. Standard module handlers use the stateless
builder. Each job still needs local space for its temporary manifest, status
and feed ZIP. Credentials and request parameters stay in worker memory.

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
