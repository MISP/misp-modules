# Gathering modules

Gathering modules collect source data and produce complete MISP events as a
standard MISP feed. They are discovered alongside expansion, import, export and
action modules. They do not connect to a MISP instance or remember whether a
particular consumer imported an event.

## Version 1 API

Discover producers using `GET /modules`: `type` and `meta.module-type` identify
`gathering`; `mispattributes.gathering_version` is `1` and
`mispattributes.parameters` describes the source-specific JSON parameters.

```json
{
  "module": "withaname",
  "operation": "prepare",
  "parameters": {
    "date_from": "2023-06-24",
    "date_to": "2023-06-25",
    "max_events": 20,
    "deduplicate_entries": true
  }
}
```

Send this request to `POST /query`. The response transports the contents of
`manifest.json` and `<event-uuid>.json` together in a bounded, consistent snapshot:

```json
{
  "gathering_version": 1,
  "source_format": "misp",
  "manifest": {"<event-uuid>": {"info": "...", "date": "...", "timestamp": "...", "Orgc": {"uuid": "...", "name": "..."}}},
  "events": {"<event-uuid>": {"Event": {"uuid": "<event-uuid>", "info": "...", "date": "...", "timestamp": "...", "Orgc": {"uuid": "...", "name": "..."}}}}
}
```

All manifest entries have a matching complete event. Empty results contain empty
JSON objects. Failures return `{"error": "..."}` without a partial feed.
Version 1 allows at most 100 events and a 32 MiB encoded bundle. There is no
pagination, background generation, protected-event signature transport or
`hashes.csv` yet. Exceeding a limit is an error; select a smaller date range.

Standalone consumers can materialize the conventional feed directory:

```python
from misp_modules.lib.gathering import write_feed

write_feed(response, "/srv/feeds/new-generation")
```

The destination must not exist. Publish the completed directory with an atomic
rename or deployment step; the helper does not publish it automatically.

## WithAName

`withaname` reads only `https://witha.name/data/` and recognized timestamped JSON
files from that directory. It never contacts the systems listed in a configuration.
Requests do not follow redirects. A collection has a 120-second budget, an 8 MiB
per-file limit and a 16 MiB aggregate download limit, including the listing.

| Parameter | Meaning |
| --- | --- |
| `date_from` | Inclusive observation date; defaults to yesterday in UTC. |
| `date_to` | Exclusive observation date; defaults to tomorrow in UTC. |
| `max_events` | Integer from 1 to 100, default 20. Fails rather than truncating. |
| `deduplicate_entries` | Boolean, default true; collapse identical target entries within each configuration. |

Filename timestamps are interpreted as UTC. Each snapshot becomes one event,
with one `ddos-config` object per target rule. Distinct rules for the same host
remain distinct. IDs are UUIDv5; object and attribute IDs are scoped to the event.
Changing the duplicate-entry policy selects a separate event identity, preventing
different views from overwriting each other. Date filters only select events.

`target_id`, `request_id` and `use_ssl` map to the corresponding hyphenated object
relations. Bodies and headers use canonical JSON text; random placeholders remain
literal. All attributes explicitly disable correlation and IDS export because the
listed systems are victims. Each event includes a source link and a canonical
JSON attachment preserving `randoms` and unmapped fields. Top-level target and
random-definition arrays are sorted for stable generation; their source ordering
is not preserved. Daily aggregation and cross-snapshot deduplication are deferred.

## Persistent revisions

Set `MISP_MODULES_GATHERING_STATE_DIR` in the module service environment to a
durable directory writable by its service account. All workers serving the same
feed must share this directory on storage suitable for SQLite locking. Back it up
and preserve it across upgrades. It contains a SQLite index of event UUIDs,
content digests and revision timestamps, not consumer import checkpoints.

Without this setting, the development default is a service-UID-specific directory
under the system temporary directory. Losing the index can prevent a corrected
historical event from receiving a newer revision than a previously imported copy;
use durable storage in production. Separate replicas must use the same source
conversion version and revision store, or a single designated producer.

Initial revisions use the source observation timestamp. Identical event content
keeps its revision, including after a service restart. Content changes keep the
event UUID and advance its timestamp monotonically. These revisions allow MISP's
normal manifest comparison to skip repeated imports. The default object identity
preserves rule versions: a changed rule has a new object UUID. Version 1 emits no
deletion tombstones; normal MISP merge semantics can retain old rule objects after
a historical source correction.

## Adding another producer

1. Add `misp_modules/modules/gathering/<name>.py` with `handler`, `version` and
   `introspection`, using `module-type: ["gathering"]` and `gathering_version: 1`.
2. Publish the parameter schema in introspection; validate it before fetching.
   Existing module `config` and server-local defaults remain available for source
   credentials. Collection parameters and service credentials are separate.
3. Build events with stable source, event, object and attribute identities.
   Include all data that affects meaning in the revision digest, and exclude
   volatile retrieval times. Scope IDs to distinct content-filtered views.
4. Use `FeedBuilder.add(event, source_timestamp)` and `FeedBuilder.build()`.
   Reject partial or oversized collections rather than silently omitting data.
5. Test source mapping, retries, reordered input, corrections, limits and the
   discovery/query contract with fixtures. No MISP source-specific code is needed.
