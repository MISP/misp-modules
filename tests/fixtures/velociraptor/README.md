The rows in `results.jsonl` are synthetic, not data collected from endpoints.
They exercise the columns in the upstream Windows.System.Pslist,
Windows.System.Services, Windows.Network.NetstatEnriched/Netstat, and
Windows.Search.FileFinder definitions linked in the importer usage guide.

`_Source`, ClientId, FlowId, HuntId and Fqdn annotate a mixed result export.
The records deliberately repeat a PID on two hosts, include an IPv6 socket,
service command-line quoting, file metadata-change time and an unmapped
nanosecond Timestamp. Hashes and client/flow/hunt identifiers are test values.
