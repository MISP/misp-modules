# VulDB expansion

The `vuldb` module queries the [VulDB API](https://vuldb.com/kb/api) and returns
standard MISP vulnerability objects related to the original input attribute.
It uses API version 3 at `https://vuldb.com/?api` and requires a VulDB API key.
VulDB is a separate service from the existing `vulndb` module.

## Supported inputs

| Attribute type | Example | API request |
| --- | --- | --- |
| `vulnerability` | `CVE-2014-6271` | Exact `advancedsearch=cve:CVE-2014-6271` |
| `vulnerability` | `VULDB-67685` or `67685` | `id=67685` |
| `cpe` | `cpe:2.3:a:gnu:bash:3.2:*:*:*:*:*:*:*` | `search=<CPE>` |

CVE and VULDB prefixes are case insensitive. A CVE can match multiple VulDB
entries, each of which becomes a separate object. Entries without a CVE still
have their `VULDB-<id>` identifier. VulDB labels CPE search experimental;
review product and version applicability before using these matches.

## Configuration

Enable the enrichment service and `Plugin.Enrichment_vuldb_enabled` in MISP's
plugin settings after installing the modified package and restarting
misp-modules. Set the corresponding `Plugin.Enrichment_vuldb_<option>` settings:

| Option | Default | Meaning |
| --- | --- | --- |
| `apikey` | Required | Personal VulDB API key, sent in the `X-VulDB-ApiKey` header. |
| `details` | `false` | `true`/`false` or `1`/`0`; request full entry details. |
| `limit` | `10` | Integer from 1 to 100; maximum entries requested and processed. |
| `timeout` | `30` | HTTP timeout in seconds, greater than 0 and at most 120. |

Null or blank optional settings use the defaults. Basic queries cost one API
credit per request according to VulDB's documentation. Full details cost one
credit per returned entry and require the appropriate access, including archive
access for older entries. The account's subscription can further restrict results.

Each enrichment makes one POST request, without retries or automatic pagination.
The result is a bounded set of matches, not a complete vulnerability inventory.
VulDB recommends at most 30 requests per minute; control bulk enrichment at the
caller. HTTP and API authentication, subscription and rate errors are returned
to MISP. An empty result returns `{"results": {}}`.

## Output

Each vulnerability object includes its VulDB ID, available CVE IDs, title,
disclosure date (`advisory.date`), modification date and VulDB link. Available
details add the description, impact, advisory URL, CPEs and a CVSS base score
with its matching vector. CVSS v3 is preferred over v2; within a version,
VulDB's score is preferred, then NVD's, then the CNA's. The score and vector
include a comment identifying their version and producer. CVSS v4 is not mapped.
Missing fields are omitted. Retrieved object attributes have `to_ids=false`.
The original input is preserved and every object references its UUID.

Example request to the module server's `/query` endpoint:

```json
{
  "module": "vuldb",
  "attribute": {
    "type": "vulnerability",
    "value": "CVE-2014-6271",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
  },
  "config": {
    "apikey": "YOUR_VULDB_API_KEY",
    "details": "false",
    "limit": "10",
    "timeout": "30"
  }
}
```

Run the offline tests with `poetry run pytest tests/test_vuldb.py`.
