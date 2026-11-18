# BeaconBeagle gathering

Collect the public [BeaconBeagle API](https://beaconbeagle.com/api/) into a
standard MISP feed ZIP using gathering contract version 2. No API key is needed.

Submit to `POST /query`:

```json
{
  "module": "beaconbeagle_gathering",
  "operation": "prepare",
  "parameters": {
    "dataset": "all",
    "page_size": 100,
    "max_events": 0
  },
  "config": {}
}
```

Poll `GET /gathering/jobs/<job_id>`, download
`GET /gathering/jobs/<job_id>/feed.zip` when ready, and release the job with
`DELETE /gathering/jobs/<job_id>`. The archive contains `manifest.json` and
`<event-uuid>.json` files. See the [gathering guide](../mkdocs/gathering-guide.md)
for storage, cancellation, revisions and retention settings.

Every generated event carries the local origin tags
`misp-gathering:module="beaconbeagle_gathering"` and
`misp-gathering:source="beaconbeagle.com"`, also present in the manifest. These
apply to configurations, beacons and C2 records. See
[local origin tags](../mkdocs/gathering-guide.md#local-origin-tags) for import and
synchronisation behavior.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `dataset` | `all` | `configs`, `beacons`, `c2`, or all three |
| `date_from` | unbounded | Inclusive UTC date of a record's latest observation |
| `date_to` | unbounded | Exclusive UTC date of a record's latest observation |
| `page_size` | 100 | Listing request size, 1–500 |
| `max_events` | 0 | Event budget; 0 is unlimited. Exceeding a positive budget fails the job. |

Collection follows offset pagination on `/configs/latest`, `/beacons` and `/c2`,
then fetches each unique record's details. Configuration summaries can repeat
across architectures or locations; each configuration hash is collected once.
Dates select complete detail records by their latest observation across locations.
They do not cut observations out of an event or mean "last modified".
An unbounded initial run can require thousands of detail requests.

Each configuration, beacon IP and C2 key has its own stable event identity.
Events contain a source API link, complete canonical JSON attachment and mapped
`malware-config` / `ip-port` objects, IP/domain/URL attributes and available ASN
context. C2 ASN attributes include `ip_enrichment[IP].ASN.number`, deduplicating
ASNs repeated across addresses or top-level metadata. Configuration locations
accept both IPs and hostnames; C2 endpoint objects retain the hostname alongside
resolved IPs with their port and protocol.
Configuration settings retain instruction order. Unknown fields,
watermarks, architecture, current/historical status, country, enrichment and
embedded configuration references remain in the source attachment.
Configuration hashes identify decoded configurations and are never emitted as
malware sample SHA-256 attributes. Observed endpoints use available first/last
seen times; configured C2 names have no invented observation time.

All generated attributes have `to_ids=false` for analyst review. The source can
include legitimate testing infrastructure. Distribution defaults to organisation
only. Stable UUIDs and the gathering revision store support repeat imports and
source corrections; ordinary MISP merging may retain older attributes. A record
without observation times uses the Unix epoch rather than retrieval time.

Requests use TLS verification, finite timeouts, no redirects, cancellation checks
and a 16 MiB response budget. HTTP errors (including rate limits), invalid records
and incomplete pagination fail generation; the framework exposes no partial ZIP.
BeaconBeagle's API has no snapshot cursor, so concurrent upstream changes can
shift offset pages; the feed represents a best-effort live collection.
