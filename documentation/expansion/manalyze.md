# Manalyze

Analyze a PE attachment or malware sample using [Manalyze](https://github.com/JusticeRage/Manalyze) installed on the misp-modules server. Analysis is local and static. The module does not upload samples to Manalyzer.org or execute them.

Install Manalyze following its [installation instructions](https://docs.manalyzer.org/en/latest/obtaining-manalyze.html), including the bundled plugins, configuration and YARA rules. Check that the account running misp-modules can run the executable and read those files. No additional Python dependency is required.

Configuration:

| Option | Default | Meaning |
| --- | --- | --- |
| `binary` | `manalyze` | Executable name on PATH or full executable path; no command-line arguments. |
| `timeout` | `60` | Analysis timeout in seconds, from 1 to 300. |
| `max_size_mb` | `25` | Maximum decoded attachment/archive and extracted sample size in MiB, from 1 to 100. |

Input is a MISP `attachment` or `malware-sample` attribute containing `type`, `value`, `uuid` and base64 `data`. Malware samples must be ZIP archives containing one sample, optionally accompanied by MISP's `.filename.txt` metadata. The attribute value must be `filename|md5`; the extracted sample is verified against that MD5. The ZIP password is `infected`; unencrypted archives also work. Filenames from attributes and ZIP entries are never used as filesystem paths. The module writes the bytes to a private temporary file named `sample.exe` and removes it after analysis, including on failure.

The command selects `--output=json --dump=all --hashes` and the offline plugins `imports,mitigation,resources,peid,compilers,findcrypt,strings`. It does not select `all` or the VirusTotal plugin. Run the module with a trusted Manalyze installation under the same isolation and resource controls used for other file parsers. Captured JSON is stored in a temporary file; reports larger than 20 MiB are rejected after the process finishes. The timeout bounds process runtime, but the module does not impose an operating-system disk or memory quota.

Results use `misp_standard`:

- The source attribute retains its UUID and metadata.
- A `file` object contains the original filename, byte size and locally computed MD5, SHA-1 and SHA-256, and references the source.
- Each plugin yields a `malware-analysis` object with product `Manalyze`, the plugin name, its summary (when present), and its own verdict: 0 → `benign`, 1 → `unknown`, 2 → `suspicious`, 3 → `malicious`. These objects reference the file and the report annotation. Verdicts describe each plugin's limited scope, not an aggregate judgment of the file.
- An `annotation` object references the file and preserves the complete single-file JSON report as `manalyze.json`, including PE headers, sections, imports, hashes and arbitrary plugin output. The temporary input path used as the CLI's outer report key is omitted.

All newly created attributes have `to_ids=false`. Existing MISP object templates cover these fields; no new template is required. Invalid requests, oversized samples, invalid archives, non-PE inputs, missing executables, timeouts, process failures and malformed or empty reports return an error without fabricated findings.

For a request example, set `module` to `manalyze` and provide:

```json
{
  "module": "manalyze",
  "attribute": {
    "type": "attachment",
    "value": "program.exe",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
    "data": "<base64-encoded PE bytes>"
  },
  "config": {"binary": "/opt/Manalyze/bin/manalyze", "timeout": "60", "max_size_mb": "25"}
}
```

Tests: `pytest tests/test_manalyze.py`. Unit tests use the documented native JSON format and mock the analyzer; they do not require the executable. The encrypted ZIP fixture checks password handling independently of Manalyze.
