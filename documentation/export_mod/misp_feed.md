# MISP Feed Export

`misp_feed` turns the **selected events** into a downloadable ZIP containing a
standard MISP feed: `manifest.json`, `hashes.csv`, and `<event-uuid>.json` for each
exported event. It uses PyMISP's `MISPEvent.to_feed(with_meta=True)`, as does the
[PyMISP feed generator](https://github.com/MISP/PyMISP/tree/main/examples/feed-generator).
No MISP API key, output directory or publishing credentials are sent to this
module. It serializes the supplied selection without fetching more events.

## Selecting a set of events

The misp-modules export protocol already accepts `data` as a list of events.
The current MISP single-event export menu invokes `events/exportModule` with one
ID. Its selected-events export dialog traditionally lists built-in formats only;
`inputSource: event-collection` alone does not add module formats to that dialog.

The companion MISP collection-export change adds enabled collection-capable
modules to the existing selected-events export format selector. With that change:

1. Enable `Plugin.Export_services_enable`, `Plugin.Export_misp_feed_enabled` and
   `MISP.background_jobs`. Run a **cache worker** and install PHP ZIP support on
   MISP. Configure the export module service as usual.
2. Filter the event index by the intended tags, organisation, dates or other
   criteria, then select the event checkboxes you want to include.
3. Use the existing export-selected-events action and choose **MISP Feed Export
   (module)**. The selection is submitted using POST and a background job starts.
4. Follow the progress page, then download the completed ZIP. The download is a
   streamed file; the complete archive does not pass through PHP as base64.

This exports the selected IDs using the current user's permissions. It does not
replay every search result across pages or fetch events hidden from that user.
For repeated manual exports, a dedicated event tag such as `feed-export:partner`
provides an easily reviewed selection. Module settings are administrator-managed,
not parameters supplied by the person downloading a feed.

The collection route accepts numeric MISP event IDs, not UUIDs. The source event
UUIDs are preserved in the feed files. REST callers can POST to
`/events/restSearchExport` with `eventid: [12, 34]` and
`returnFormat: module_misp_feed`, receive HTTP 202 with a job ID/status/download
URLs, poll status, and download when ready. The queue request fetches no event
bodies and does not wait for serialization.

Without the companion MISP change, single-event export and bounded synchronous
`/query` calls still work. Inline calls are limited to 1000 events and 128 MiB
uncompressed (or a lower configured size limit). Large selections must use the
background route; they must not be sent as one JSON export request:


```json
{
  "module": "misp_feed",
  "data": [
    {"Event": {"uuid": "...", "info": "...", "Orgc": {"name": "...", "uuid": "..."}, "published": true, "distribution": 3, "date": "2026-11-09", "timestamp": 1794200000, "Attribute": []}},
    {"Event": {"uuid": "...", "info": "...", "Orgc": {"name": "...", "uuid": "..."}, "published": true, "distribution": 3, "date": "2026-11-09", "timestamp": 1794200000, "Attribute": []}}
  ]
}
```

The ellipses stand for the original event and creator UUIDs and metadata. Events
must include their source UUID, creator name/UUID, info, date, timestamp,
publication state and distribution. Standard wrapped, flat, and legacy core
export envelopes are accepted; explicit collections beside `Event` take
precedence, including empty collections. `data: {"response": [...]}` is also
accepted for a native MISP JSON search result. The response's `data` field is
base64-encoded ZIP data.

## Feed contents and filtering

Default policy includes **published events with distribution 3 (All)**, and
attributes/objects/reports with distribution 3 or 5 (inherit). Deleted data,
non-exportable tags and local tags are excluded. Both IDS and non-IDS attributes
are retained. Attribute values, comments, objects, available attachment data and
exportable reports can be present in the archive; review the selection before
publishing it. Distribution metadata is omitted by default, as in the standalone
generator. Static hosting permissions determine who can download a feed.

| `Plugin.Export_misp_feed_...` setting | Default and behavior |
| --- | --- |
| `valid_distributions` | `3,5`; comma-separated allowed distribution levels. Controls events and nested attributes/objects/reports. Set explicitly for a private feed containing other levels; it is not a replacement for hosting access control. |
| `include_unpublished` | false; explicitly include unpublished events when true. |
| `with_distribution` | false; include distribution and sharing-group metadata when true. |
| `with_local_tags` | false; include exportable local tags on events and attributes when true. |
| `exclude_attribute_types` | Empty; comma-separated MISP types to remove from both event and object attributes before serialization and hashing. |
| `max_events` | 0, meaning no count limit for background generation; optionally set a positive aggregate limit. A larger selection fails rather than truncating. |
| `max_size_mb` | 10240 MiB aggregate uncompressed feed budget. Set a positive size or explicitly 0 for no aggregate size cap. The worker enforces this across all parts. |
| `max_event_size_mb` | 128; maximum size of one serialized event part, configurable up to 2048 MiB. |

Boolean values accept true/false, 0/1 and their string forms. Missing/null/empty
settings use defaults. An invalid event, duplicate event UUID, unsupported
protected event or exceeded limit produces an error and **no downloadable partial
archive**. A selection excluded entirely by policy also returns an error.

Association-level local flags on `EventTag`/`AttributeTag` records are preserved
before filtering, including when a nested Tag object has a different local flag.
Duplicate tag representations use the restrictive local/exportable state.

Manifest entries and MD5 correlation hashes are generated from the same filtered
events. `hashes.csv` uses the generator's `hash,event_uuid` format, with no header;
these hashes index attribute values, not file integrity. Event/object local IDs
are removed by the native feed serializer. Object references to excluded data
are omitted. Original UUIDs/timestamps remain stable, and the module does not
create new identities or publish source events. No signatures are generated;
protected events require the standalone generator's signature workflow.

## Making the snapshot a feed

1. Extract the ZIP into a dedicated directory. All files are at its root.
2. Publish that directory on an appropriate HTTPS server, or copy it to a local
   directory readable by the consuming MISP. For updates, replace the entire
   generated directory atomically so manifest and event files stay consistent.
3. On the consuming MISP, use **Sync Actions → List Feeds → Add feed**, choose
   **MISP Feed** as source format, and supply the directory's base URL or local
   path. The source is the extracted directory, **not the ZIP download URL**.
4. Enable/cache/fetch the feed according to the consumer's normal policy.

An event removed from a later manifest is no longer advertised; this does not
revoke copies already downloaded or delete previously imported events. Changing
export filters without changing source event timestamps may require a forced
update on consumers to refresh an already imported event.

## Choosing a workflow

| Need | Suitable approach |
| --- | --- |
| One reviewed snapshot of selected events | This export module and the collection export selector. |
| A continuously refreshed feed selected by tags, organisation or dates | Schedule the existing PyMISP generator with saved filters and deploy its complete output directory atomically. This also supports signed protected events. |
| Regular exchange between two connected MISPs with per-user access controls | Consider native MISP synchronisation and its filters. |
| Large on-demand feeds | The collection background worker described below. |
| Automatic feed publication | A scheduled generator and deployment step; the export does not publish to a web root or object store. |

## Background generation and large selections

The companion MISP worker fetches **one event at a time** using the submitting
user's ACLs and sends `feed_chunk: true` with one event to this module. It
preserves the legacy association wrappers so local-tag flags are not lost in
older JSON converters; the module normalizes both legacy and standard input. Each response is a bounded one-event ZIP with its native
manifest/hash index and aggregate `feed_limits`. A policy-filtered event produces
an empty part; an invalid event produces an error. The worker streams event files
and indexes to private disk storage and builds the final ZIP from files. It never
loads the complete event set, manifest, hash index or final base64 ZIP in memory.
Memory still includes the selected ID list, the largest individual event and ZIP
central-directory metadata, so it is not independent of every input dimension.

Generation runs in the native CLI cache worker with PHP's execution time limit
disabled. There is **no web-request timeout covering the whole feed**. Individual
module requests have a 120-second metadata default; adjust
`Plugin.Export_misp_feed_execution_timeout` for unusually expensive events. Network
failures, per-event limits, disk exhaustion and operator/supervisor process limits
can still fail a job. Failed or interrupted jobs never offer a partial archive;
submit a new selection to retry. Background jobs are required for this route; it
does not silently fall back to a long synchronous request.

The submitting account and module permissions are refreshed during generation;
event visibility is checked for each fetch. Only the submitting user can read
status/download URLs, and module permission is rechecked on download. Ready
artifacts expire after 24 hours. Private files live under
`app/tmp/module_feed_exports` on MISP, which must be shared between the web and
worker processes. Allow disk space for uncompressed staging **plus** the final
ZIP. Expired files are purged on new submissions; operators can schedule
`cake event purgeModuleFeeds` to remove them when no new jobs are submitted.

Validation on a synthetic 5000-event feed (21 attributes per event, including
64 KiB of random context) produced 361,162,786 bytes of uncompressed per-event
feed data and a 194,404,858-byte final archive. Python serialization took 24.59 s;
PHP assembly took 33.45 s. Python peaked at 104,256 KiB RSS for both 100 and 5000
events. The PHP assembler peaked at 27,536 KiB RSS (10 MiB PHP-managed heap),
including final manifest verification. The assembly benchmark starts PHP with a
one-second execution limit and disables it as the real CLI worker does. These
are local measurements, not a guarantee for every event shape or deployment.

Reproduce with `tests/benchmark_misp_feed.py` in misp-modules and
`app/Test/benchmark_module_feed_export.php` in MISP. The HTTP regression also
serializes a sequence of parts whose total duration exceeds a one-second request
deadline while every individual request succeeds.

The module creates a portable feed artifact. It does not schedule refreshes,
register feeds, sign events or publish to external storage.

For a full artifact check after the benchmark, run
`PYTHONPATH=. python tests/benchmark_misp_feed.py --verify-archive /path/to/feed.zip`.
The 5000-event result passed all event/manifest UUID checks, all 105000 MD5 lookup
rows and all ZIP CRC checks.
