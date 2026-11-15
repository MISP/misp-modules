# Native Zeek and Suricata fixture provenance

The committed logs were emitted by **Zeek 9.0.1** and **Suricata 8.0.8**, processing
the same synthetic 10-packet HTTP/DNS PCAP in network-disabled disposable containers.
No production sensor, live packet capture or case data was used. Logs were copied
unchanged from each tool; they are not hand-converted examples.

- `zeek-{conn,dns,http,notice}.jsonl`: native JSON writer output.
- `zeek-{conn,dns,http,notice}.log`: native typed ASCII writer output, with headers,
  unset fields, booleans, counts, sets and fixed-point timestamp tokens.
- `suricata-eve.jsonl`: native alert, HTTP, fileinfo, DNS, flow and stats records.
- `manifest.json`: producer versions, pinned image digests, input capture name and
  SHA-256. The hash describes the synthetic PCAP bytes created by the generator,
  not any of the log files.

The synthetic capture uses reserved documentation IPs and `example.test`, with a
complete TCP HTTP exchange and UDP DNS request/answer. A local Suricata rule with
SID 1000001 and a local Zeek notice policy produce benign test observations.
Community ID logging is enabled with the tools' default seed; both native tools
emit matching IDs for the two flows. Zeek UIDs and capture processing timestamps
may change when fixtures are regenerated. Native JSON duration values can expose
floating-point tails; tests ensure these are not rounded into invented end times.

`reproduce.py` uses only the Python standard library and Docker for reproduction:

```sh
python tests/fixtures/network_observation/reproduce.py
```

Pull the pinned images listed in that script first. The script creates only its
own disposable containers with `--network none`, copies synthetic input files into
them, retrieves the logs and removes the containers. It does not bind-mount host
directories or access host capture interfaces. Local generation artifacts default
to `/workspace/work/network-native`; override `NETWORK_FIXTURE_WORK` if needed.
Ordinary module tests use committed logs and require neither Docker nor either tool.

Reviewed format definitions:

- [Zeek 9.0.1 connection record](https://github.com/zeek/zeek/blob/v9.0.1/scripts/base/protocols/conn/main.zeek)
- [Zeek ASCII logging](https://docs.zeek.org/en/stable/log-formats.html)
- [Suricata 8.0.8 EVE schema](https://github.com/OISF/suricata/blob/suricata-8.0.8/doc/userguide/output/eve/eve-json-format.rst)
- [Suricata Community ID logging](https://github.com/OISF/suricata/blob/suricata-8.0.8/doc/userguide/output/eve/eve-json-output.rst)
