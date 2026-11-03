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
4. Use stable UUIDs throughout and include meaningful content in revisions.
   Exclude volatile retrieval timestamps and scope content-filtered views.
5. Test reordered data, retries, corrections, limits and job lifecycle. The MISP
   integration discovers producers without a source-specific allowlist.
