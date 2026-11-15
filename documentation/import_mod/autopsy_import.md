# Autopsy / Mobile Forensic Selected Results Import

Imports selected browser, download, communication and installed-application
artifacts from:

- Autopsy's **Export Selected Rows to CSV** action, using the English display
  labels or canonical TSK attribute names.
- The explicit **misp-forensic-selected version 1 JSON interchange** below,
  suitable for mobile parsers or case-specific exporters.

This is an offline result importer. It does not open case databases or images,
fetch referenced source paths, retrieve attachment links, contact devices,
execute report content or infer a malicious verdict.

## Autopsy CSV

In Autopsy, select rows from one artifact family and export them to CSV.
Supply that family's TSK name in config.artifact_type. An illustrative API
request is:

    {
      "module": "autopsy_import",
      "filename": "selected-history.csv",
      "data": "<base64 of the exported CSV bytes>",
      "config": {
        "artifact_type": "TSK_WEB_HISTORY",
        "case_id": "case-123",
        "data_source_id": "17",
        "timezone": "+01:00"
      }
    }

Native CSV columns vary with artifact family, Autopsy version and UI language.
The importer recognizes the documented English labels; it does not guess an
artifact type from a URL or translate localized column names. Canonical
TSK_URL/TSK_DATETIME_ACCESSED/etc. columns can also be used by explicit exporters.
Unknown columns remain in the raw record. Exported display values may already
be formatted or truncated by the producer; the importer cannot restore content
that was not exported.

CSV needs UTF-8, with an optional BOM, unique nonempty headers and matching
column counts. Standard quoting, embedded newlines and commas are supported.
HTML, PDF, XLSX, case databases and ZIP bundles are not parsed.

## Selected JSON for mobile parsers

The interchange is a documented conversion target, not native commercial-format
detection. A caller must explicitly identify the tool/parser and normalize
selected artifacts into TSK field semantics:

    {
      "format": "misp-forensic-selected",
      "version": 1,
      "producer": {"name": "Example mobile parser", "version": "1.0"},
      "context": {
        "case_id": "case-123",
        "device_id": "phone-1",
        "data_source_id": "ds-1",
        "evidence_id": "extraction-1",
        "report_id": "report-1"
      },
      "artifacts": [
        {
          "artifact_type": "TSK_MESSAGE",
          "artifact_id": "458",
          "source_file": "/reported/path/to/messages.db",
          "source_object_id": "234",
          "context": {"device_id": "phone-2"},
          "attributes": {
            "TSK_MESSAGE_TYPE": "SMS",
            "TSK_TEXT": "A selected message",
            "TSK_PHONE_NUMBER_FROM": "+12025550101",
            "TSK_PHONE_NUMBER_TO": "+12025550102",
            "TSK_DATETIME_SENT": 1700000000
          },
          "native_record": {"unmapped producer fields": "retained"}
        },
        {
          "artifact_type": "TSK_INSTALLED_PROG",
          "artifact_id": "459",
          "application_id": "org.example.application",
          "attributes": {"TSK_PROG_NAME": "Example App", "TSK_VERSION": "1.2"}
        }
      ]
    }

Top-level keys are format, version, producer, context and artifacts. Every row
needs an attributes object and an artifact_type, or an explicit default in
config.artifact_type. Unmapped row fields and native_record content are retained.
Producer attribution is supplied by the caller, not authenticated by the importer.

Context precedence is config defaults, envelope context, then row context.
Known identifiers are case_id, data_source_id, device_id, evidence_id and
report_id. data_source is a label, kept distinct from data_source_id.
Row-level artifact_id, source_file, source_object_id and application_id are
retained explicitly. Unknown context fields remain in source-context.

## Typed mappings

| TSK artifact type | MISP object | Required mapped information |
| --- | --- | --- |
| TSK_WEB_HISTORY | tsk-web-history | URL and an unambiguous access time |
| TSK_WEB_BOOKMARK | tsk-web-bookmark | URL |
| TSK_WEB_COOKIE | tsk-web-cookie | URL, name and nonempty value |
| TSK_WEB_SEARCH_QUERY | tsk-web-search-query | Search domain and query text |
| TSK_WEB_DOWNLOAD | tsk-web-downloads | URL and name, or a name from an explicit download destination path |
| TSK_MESSAGE | tsk-chats | Explicit message type and message text |
| TSK_EMAIL_MSG | tsk-chats | Plaintext content; message type is Email |
| TSK_INSTALLED_PROG | software | Program name; version is optional |

Browser, title, domain, referrer, reported paths, path IDs, participants,
application name, subject and explicit sent/received times are added where
the template supports them. Software display names and package/bundle IDs
remain distinct. An organization field is retained raw rather than assumed to
be an application vendor. Program presence does not establish execution.

Source File is provenance; it is not a download destination. Download names
can be derived only from an explicit TSK_PATH/Path value that includes a final
filename, never from a URL. Path IDs are retained as identifiers, not resolved.
Message participants remain text, without inferring accounts or cross-device
conversation links. A generic message Date/Time is retained as event-time;
it is not assumed to be a sent or received time.

Missing required template fields, conflicting canonical/display aliases and
unsupported types produce warnings and retain the forensic-artifact record
without an invalid or guessed typed object.

## Time handling

Canonical TSK DATETIME attributes use integer Unix **seconds**. Milliseconds,
floating epochs and unknown units are not guessed. Strings may be complete
ISO timestamps with explicit offsets, or Autopsy-style date/time display values.
Numeric zero follows Sleuth Kit's unknown-time sentinel and remains raw; an
intentional Unix epoch instant can be supplied as an explicit ISO timestamp.

UTC, GMT and numeric offsets can be normalized directly. Explicit prefixed
offsets such as UTC+01:00 and GMT-05:30 take precedence over config.timezone.
Local timestamps and
ambiguous abbreviations such as CST require config.timezone, set to UTC or a
known numeric offset such as -06:00 that matches the report's display settings.
IANA zones and DST transitions are not inferred. A -00:00 offset and precision
beyond six fractional digits remain raw with warnings.

The importer never substitutes its current time. Original timestamp text stays
in raw-record regardless of normalization. The JSON row text preserves numeric
precision, escaping and whitespace; CSV records preserve every cell as text in
normalized JSON. Full-export lexical bytes remain authoritative when attached.

## Selection and evidence

Every import creates a source file object with report SHA-256 and byte size,
plus one forensic-artifact provenance object per selected row. Derived objects
are linked to their provenance record with derived-from; each record links
to the source report. Report hashes do not identify the underlying device image.

The full original report is attached only when all input rows are included.
config.rows can be a list or comma-separated string of one-based data-row
ordinals, for example "2,8". CSV headers are not counted. Excluded rows cause
the full attachment to be omitted, with a warning; the full report hash and
original selected row numbers remain available. Out-of-range selections fail.
Records are not renumbered or merged merely because artifact IDs match.

All output attributes have to_ids disabled and correlation disabled.
The summary reports input, selected, mapped and unmapped counts and whether
the original report was attached. A retained record is an unreviewed observation.

## Limits and commercial adapters

Inputs are limited to 20 MiB, 1000 rows, 64 KiB per record/context and 32 nesting
levels. The MISP response is limited to 100 MiB. Invalid structure, duplicate
JSON keys, non-finite JSON numbers and malformed CSV fail without partial results.
format may be auto (default), autopsy-csv or selected-json. Optional tool_version
records the CSV producer version when known; it is never guessed.

No native Cellebrite/UFED, Magnet, XRY or Oxygen adapter is claimed. Add one
only with redistributable deidentified sample reports, documented versions and
field/time/selection semantics, regression fixtures, and a named maintainer.
Synthetic interchange fixtures demonstrate this contract and do not stand in
for native commercial samples. The bundled forensic-artifact template supports
older PyMISP versions; its companion misp-objects contribution uses the same
definition.
