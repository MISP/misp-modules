# ADTimeline import

Import native `timeline_*.csv` produced by [ANSSI-FR/ADTimeline](https://github.com/ANSSI-FR/ADTimeline), using the file import UI or `/query` with module `adtimeline_import` and base64 `data`. The file remains attached verbatim, with its SHA-256, size and sanitized basename. No Active Directory connection, PowerShell execution or remote resource access occurs during import.

The native format is semicolon-delimited CSV (`Export-Csv -Delimiter ';' -NoTypeInformation -Encoding UTF8`). UTF-8 with/without BOM and BOM-marked UTF-16 are accepted, with normal CSV quoting, multiline values and Unicode. Required columns and row values: `DN`, `pszAttributeName`, `ftimeLastOriginatingChange`. Other native columns are optional; unknown columns are retained in `raw-record`. The separate `ADobjects_*.xml` and `gcADobjects_*.xml` inventories and Splunk search exports are not supported by this importer.

Optional file-import configuration:

| Setting | Meaning |
| --- | --- |
| `domain_scope` | Collector-provided domain context; not inferred by splitting LDAP DNs. |
| `collection_server` | Collector-provided LDAP server identity, useful for scoping `usnLocalChange`. |

Each CSV data record becomes an `ad-replication-metadata` object, referencing the attached source file through `derived-from`. The template is bundled, so importing does not depend on an updated PyMISP template catalog. Identical inputs/context produce stable object and attribute UUIDs; duplicate source rows remain distinct by record index. All attributes have IDS matching and correlation disabled, and every observation starts as `unreviewed`. AD deletions and removed links remain evidence; they do not delete MISP data.

Mapped fields include the affected DN, attribute name, collected object name/class/category, SamAccountName, SID, `dwVersion`, originating DSA DN/invocation ID, originating/local USNs and `Member`. Counters remain exact text, avoiding numeric truncation. `Member` also carries `altRecipient` linked-value metadata; it is not always a group member. Current object names, account names and the originating directory server do not identify the actor who made a change. Replication metadata records last changes and linked-value history available at collection; it is not a complete audit log or a maliciousness verdict. The exporter generally does not supply attribute values or before/after values, so the importer does not invent them.

`ftimeLastOriginatingChange`, `WhenCreated`, `ftimeCreated`, and `ftimeDeleted` are always preserved as raw text when nonempty. ISO timestamps with seconds, an explicit known timezone, and at most six fractional digits are additionally normalized to UTC. The upstream `WhenCreated` format with a space and trailing `Z` is supported. Locale-dependent dates, timezone-free dates, unavailable values, unknown offsets and excess fractional precision remain raw and produce warnings. The `1601-01-01T00:00:00Z` FILETIME sentinel is retained raw without a normalized time; in particular it is not treated as a real link deletion. Exact original lexical bytes remain in the source attachment.

Limits: 10 MiB decoded input, 1,000 data records, 128 columns, column names up to 256 characters, fields up to 65,536 characters. Split or select larger timelines before upload. Missing required fields, malformed quoting, duplicate headers, inconsistent column counts, invalid encoding/base64 or exceeded limits return an error without partial results. Unrecognized timestamps are a nonfatal warning because their original evidence is retained. `summary` reports the record count and source digest.

Tests use a synthetic fixture serialized by real PowerShell, following the pinned upstream field order and CSV export settings; see [fixture provenance](../../tests/fixtures/adtimeline/README.md). They do not require an AD environment. Native Windows collection against a live domain has not been exercised here.
