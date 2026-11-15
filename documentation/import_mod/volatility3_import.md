# Volatility 3 results import

`volatility3_import` ingests already produced memory-analysis results. It accepts
native Volatility 3 JSON and JSONL, including nested renderer `__children` rows.
It does not open a memory image, execute plugins, load rules, fetch symbols or
contact a service. Volatility itself is not an importer dependency. This workflow
is separate from the older `volatility-misp` YARA-rule retrieval plugin.

The initial mappings cover these Windows plugins plus layer-wide YARA scans:

| Producing plugin | Derived observations |
| --- | --- |
| `windows.pslist.PsList`, `windows.psscan.PsScan` | Process PID/PPID, name and creation time; physical/virtual offsets remain on the result. |
| `windows.pstree.PsTree` | Process observations with command/path context and explicit, consistent parent links. |
| `windows.cmdline.CmdLine` | Process name/PID and the original command line, without parsing Windows quoting. |
| `windows.netscan.NetScan`, `windows.netstat.NetStat` | Process ownership context and IPv4/IPv6 network sockets. |
| `windows.malware.malfind.Malfind`, legacy `windows.malfind.Malfind` | Unreviewed suspicious regions with start/end addresses, protection, VAD tag and raw hexdump/disassembly. |
| `windows.vadyarascan.VadYaraScan` | Unreviewed YARA matches with process context, offset, rule name, component and matched bytes. |
| `yarascan.YaraScan` | Layer-wide YARA matches; no process identity is invented. |

The class suffix may be omitted (for example `windows.pslist`). Bare `pslist`,
unsupported plugins and mismatched column schemas are rejected rather than
classified by similar column names. Linux/macOS plugins, CSV, text tables and
native memory images are outside this initial mapping set. Optional newer plugin
columns are retained even if they have no normalized MISP relation.

For example, generate the source export with Volatility 3:

```sh
python vol.py -q -f memory.raw -r json windows.pslist.PsList > pslist.json
```

Use `-r jsonl` for native JSONL. Preserve stdout as UTF-8 JSON/JSONL; banners or
progress mixed into the file are not accepted. A normal module import request
uses `module: "volatility3_import"`, base64-encoded export bytes in `data`, an
optional `filename`, and these `config` values:

| Setting | Meaning |
| --- | --- |
| `plugin` | Required producer plugin identity; not guessed from columns or filename. |
| `format` | `auto` (default), `json` or `jsonl`. Explicit formats are enforced. A single JSONL root may also be valid JSON in automatic mode. |
| `image_sha256` | Optional exact memory-image SHA-256, supplied by the producer. Distinct from the hash of the results export. |
| `image_name` | Optional memory-image name/reference, with a valid basename. Never opened or fetched. |
| `volatility_version` | Optional producing Volatility 3 version. |
| `plugin_version` | Optional plugin class version, which is separate from the framework/package version. |
| `layer_name` | Optional memory layer reference, particularly useful for global YARA scans. |

Native renderer output does not provide the image hash or tool/plugin versions.
Supply them alongside the export when available; missing values generate warnings
and are never inferred from the JSON bytes, columns or the importer's environment.
The producer is responsible for their accuracy; the importer does not verify the
underlying memory image.

Collectors may instead wrap an unmodified native results array:

```json
{
  "metadata": {
    "plugin": "windows.pslist.PsList",
    "volatility_version": "2.28.2",
    "plugin_version": "3.0.1",
    "image_name": "memory.raw",
    "image_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "results": []
}
```

Replace `results` with the actual non-empty export array and use the real image
hash and producer versions. Context can be supplied in either metadata or config;
conflicting values return an atomic error. Plugin aliases and SHA-256 case are
normalized before comparison. Unknown wrapper metadata remains in the exact
attached export; it is not promoted into MISP attributes.

Each source row becomes a `volatility3-result`, using the companion template
bundled for older PyMISP installations. It records image provenance, plugin and
version context, source hash, row index/path, exact raw columns, offsets and
relevant memory/YARA/time fields. The existing `process`, `network-socket` and
`file` templates represent normalized observations and source files. All imported
attributes are non-IDS and non-correlating, including image hashes and IPs.

The original export is attached to a source `file` with its own SHA-256 and byte
count. A separate memory-image `file`, when identifiable by supplied name/hash,
contains only those references. The image points to the export, the export points
to result rows, and result rows point to normalized observations using the
catalogue's `derived-from` direction (source to derived target). Result rows also
`describe` those observations.

Renderer hierarchy is preserved by `row-path` and `contains` references between
results, excluding `__children` from each row's raw columns to avoid repeated
subtrees. Process `parent-of` links are added only for explicit `pstree` nesting
with matching PPID/PID, distinct process IDs and no contradictory known creation
times. PID alone never merges rows or correlates processes across images/runs.
A flat PPID value remains a field, not an inferred relationship.

Offsets use integer arithmetic and normalize to hexadecimal without precision
loss, including addresses above JavaScript's exact integer range. Only an explicit
`Offset(V)`/`Offset(P)` label determines virtual/physical scope. A generic `Offset`
is plugin/layer-specific. Source values remain in the raw record. Addresses are
not dereferenced, and region addresses are not multiplied as page numbers.

Creation/exit times require an explicit known timezone and at most microsecond
precision. Local times, unknown `-00:00` offsets, numeric times without declared
semantics and higher precision remain raw with a warning; no rounding or epoch
guessing occurs. Network `Created` is retained as network-object creation time,
never relabeled as a first-packet observation. Wildcard endpoints and unavailable
values do not become fake IPs; corrupt PIDs/ports/addresses remain raw with warnings.
PID/PPID values must be integers in the range 0–4294967295 before appearing on
either result or process objects. Zero is retained; invalid identifiers are not
promoted from raw context and cannot establish process-parent links.

`malfind` suspicion and YARA matches always start as `unreviewed`. A rule name is
not a rule body, and none of these rows independently confirms malicious activity.
Analyst-confirmed conclusions can be represented separately. Native dumping paths,
hex bytes and disassembly remain source context; no file is opened or executed.

Limits: 20 MiB input, 1000 rows including children, 128 KiB per normalized row,
32 renderer hierarchy levels and 32 levels of nested column data. Empty results,
invalid structure, duplicate JSON keys, non-finite numbers, invalid explicit
configuration and schema mismatches return atomic errors. Recoverable unmapped
field/time problems are counted in API warnings and retain their raw values.

Validation uses Volatility 3 2.28.2's unchanged native JSON/JSONL renderer and
plugin column schemas with synthetic rows. No real memory dump/plugin analysis
was executed. See [fixture provenance](../../tests/fixtures/volatility3/README.md).
