# Cuckoo and CAPE report imports

Use the `cuckooimport` import module to upload a standalone JSON analysis report,
a ZIP archive, or a bzip2 tarball. Archives must contain `reports/report.json`
or `report.json` as a regular file. The module reads members in memory and does
not extract them to the filesystem or follow archive links.

For CAPEv2, `/apiv2/tasks/get/report/<task_id>/json/` returns the standalone
report. The `all` format returns a ZIP containing the report and analysis files
when that download is enabled on the CAPE server. A standalone report contains
metadata, not the submitted binary, dropped files, or screenshots. The importer
preserves reported filenames and hashes without creating empty attachments.
Use a full archive to import the actual files and screenshots.

Import options control each section. Omitted options use the defaults advertised
by `introspection()`; pass `0` to disable a section. The existing **Upload sample**
option imports target file metadata even when its binary is absent. **CAPE
configurations** preserves each `CAPE.configs` entry as JSON text in an annotation
object; it does not infer additional indicators from arbitrary configuration keys.
Other CAPE-specific sections, such as `CAPE.payloads`, are not mapped by this
importer. The separate `cape_sandbox` expansion module supports report retrieval
by task ID through the CAPE API; this importer accepts uploaded reports.

## CAPEv2 format review

The compatibility fixture in `tests/fixtures/cape_report.json` is synthetic and
contains reserved example addresses and invented hashes, with no malware. Its
field layout was checked against CAPEv2 commit
[`8d1729f26f60784e1a75175b2ac8e1d73b4c01bd`](https://github.com/kevoreilly/CAPEv2/tree/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd):

| Section | Current CAPE format | Import behavior |
| --- | --- | --- |
| JSON export | `JsonDump` writes the results object directly; API v2 streams `report.json` | Read standalone JSON as well as report archives |
| Sandbox metadata | Top-level `malscore`; `info.started`; optional `info.machine` | Preserve the score and available analysis details without requiring a machine |
| Processes | `pid`, `name`, `parent_id`, `module_path`, `environ.CommandLine`, `children` | Map fields into process objects and retain parent/child references |
| Network | TCP/UDP `time` is relative to the capture; DNS/HTTP retain their Cuckoo layouts | Preserve the relative offset in the connection comment; do not treat it as a Unix timestamp or assume the capture started at `info.started` |
| Signatures | `description`, `data`, `new_data`; ATT&CK mappings in top-level `ttps` | Preserve signature details and corresponding technique IDs |
| Dropped files | `name` can be a list; guest locations in `guest_paths` | Retain filename, hashes and guest paths; attach bytes only when present |
| Configurations | `CAPE.configs` is a list of extracted configuration objects | Preserve each configuration as JSON text |
| Screenshots | ZIP analysis files include `shots/*.jpg` or `shots/*.png` | Import available archive images; skip absent files |

Source files reviewed: [JSON export](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/modules/reporting/jsondump.py),
[API](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/web/apiv2/views.py),
[analysis metadata](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/modules/processing/analysisinfo.py),
[process trees](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/modules/processing/behavior.py),
[network](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/modules/processing/network.py),
[signature results](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/lib/cuckoo/common/abstracts.py),
[scoring and ATT&CK](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/lib/cuckoo/core/plugins.py),
[dropped files and configurations](https://github.com/kevoreilly/CAPEv2/blob/8d1729f26f60784e1a75175b2ac8e1d73b4c01bd/modules/processing/CAPE.py).

This verifies the importer against upstream field definitions and offline
fixtures. It does not replace validation against a private CAPE deployment or
the original report from issue [#502](https://github.com/MISP/misp-modules/issues/502),
which includes neither a report nor a traceback.
