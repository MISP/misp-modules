# Fixture provenance

`hayabusa.json`, `.jsonl` and `.csv` are actual exports from Hayabusa **4.4.0**.
`chainsaw.json` and `.jsonl` are actual exports from Chainsaw **2.17.1** using its
native benign test rule. `chainsaw-sigma.json` uses the included benign Sigma rule
and Chainsaw's upstream `mappings/sigma-event-logs-all.yml`.

Input: the public 68 KiB [security_sample.evtx](https://github.com/WithSecureOpenSource/chainsaw/blob/649dc5b497e584b9e1339b0a51d0d88aaf50f195/tests/evtx/security_sample.evtx).
The native Chainsaw [test rule](https://github.com/WithSecureOpenSource/chainsaw/blob/649dc5b497e584b9e1339b0a51d0d88aaf50f195/tests/evtx/rule-any-logon.yml)
is `rule-any-logon.yml`. These test matches identify logon events and do not claim
that the sample contains malicious activity.

Reproduction, with binaries/rules/configuration from the stated releases:

```sh
# In a Chainsaw working directory containing the sample, native test rule and mapping:
chainsaw --no-banner hunt security_sample.evtx -r rule-any-logon.yml --json -q > chainsaw.json
chainsaw --no-banner hunt security_sample.evtx -r rule-any-logon.yml --jsonl -q > chainsaw.jsonl
chainsaw --no-banner hunt security_sample.evtx -s ../hayabusa/test-logon.yml --mapping mapping.yml --json -q > chainsaw-sigma.json

# In the Hayabusa directory, with the included test-logon.yml:
hayabusa dfir-timeline -f ../chainsaw/security_sample.evtx -r ./test-logon.yml -w -q -N -Q -U -b -A -a -C -p super-verbose -t json -o hayabusa.json
# Repeat with -t jsonl and -t csv for the other formats.
```

Paths are the relative paths reported by the tools. The files retain the tool
output bytes. Hayabusa's JSON file is a stream of pretty-printed objects, not a
JSON array. Tests do not need either binary and make no network calls.

`chainsaw-aggregate.json` is **synthetic**, derived from the native event shape to
exercise a single Sigma detection with two documents on different hosts/channels
and the same record ID. It does not claim to be an observed multi-host attack.
