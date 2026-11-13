# AssemblyLine Query

Query an AssemblyLine submission link and return the parsed MISP attributes,
objects and tags. Configure `apiurl`, `user_id` and either `apikey` or `password`.
The optional `verifyssl` flag defaults to `true`.

## Optional debug logging

The module configuration flag `debug` defaults to `false`. Set it to boolean
`true` or a string such as `true`, `1`, `yes` or `on` to log the full parsed MISP
event while troubleshooting. String values ignore case and surrounding
whitespace. Omitted values, `false`, `0`, `no`, `off` and unrecognised strings
leave this logging disabled.

For example, include this flag alongside the usual module credentials:

```json
{
  "module": "assemblyline_query",
  "attribute": {
    "type": "link",
    "value": "https://assemblyline.example/submission/detail/submission-id",
    "uuid": "f6061c52-57d8-46fd-8c4d-043565d27b40"
  },
  "config": {
    "apiurl": "https://assemblyline.example",
    "user_id": "analyst",
    "apikey": "example-api-key",
    "debug": true
  }
}
```

Debug events use the `misp-modules.assemblyline_query` logger at `DEBUG` level
and flow through the service's existing log handlers. The module flag works
without the server's global `--debug` option. Global debug alone does not enable
these event dumps. Standalone callers must configure their own logging handler.

The logs contain the full parsed event, including indicators and classification
tags. Enable the flag only while troubleshooting and restrict access to the
configured log destination. Request configuration and authentication credentials
are not added to this event log.

The module does not create a debug file in `/tmp`, even when debugging is enabled.
The flag applies to the current query and does not enable logging for subsequent
queries. Returned enrichment results are the same with debug enabled or disabled.
