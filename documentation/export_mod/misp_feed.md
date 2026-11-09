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

1. Enable `Plugin.Export_services_enable` and `Plugin.Export_misp_feed_enabled`
   in MISP's server settings. Configure the export module service as usual.
2. Filter the event index by the intended tags, organisation, dates or other
   criteria, then select the event checkboxes you want to include.
3. Use the existing export-selected-events action and choose **MISP Feed Export
   (module)**. Download the ZIP.

This exports the selected IDs using the current user's permissions. It does not
replay every search result across pages or fetch events hidden from that user.
For repeated manual exports, a dedicated event tag such as `feed-export:partner`
provides an easily reviewed selection. Module settings are administrator-managed,
not parameters supplied by the person downloading a feed.

Without the companion MISP change, single-event export still works. A caller can
also retrieve a selected set through MISP's authenticated event search API and
pass the returned full event list to misp-modules `/query`:

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
| `max_events` | 1000; positive upper limit, configurable up to 100000. A larger input fails rather than truncating. |
| `max_size_mb` | 128; limit on total uncompressed feed files, configurable from 1 to 2048 MiB. Exceeding it fails the entire export. |

Boolean values accept true/false, 0/1 and their string forms. Missing/null/empty
settings use defaults. An invalid event, duplicate event UUID, unsupported
protected event or exceeded limit produces an error and **no downloadable partial
archive**. A selection excluded entirely by policy also returns an error.

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
| Very large feeds or automatic publishing from the UI | A background job/publisher is a separate integration; this synchronous, base64 export is intended for bounded snapshots. |

The module does not schedule refreshes, register feeds, sign events or publish to
web roots/object storage. It creates the portable feed artifact. MISP's export
service timeout and HTTP request limits still apply; raise an appropriate
per-module execution timeout when generating larger snapshots.
