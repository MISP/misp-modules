# Optional module result caching

Result caching reduces repeated queries to external services, as requested in
[issue #712](https://github.com/MISP/misp-modules/issues/712). It is disabled
unless the service starts with `--cache-config` and a module is explicitly
configured with `"enabled": true`. Existing installations require no changes.
No additional Python dependencies, database, Redis instance or persistent files
are needed.

## Enable selected modules

Create `/etc/misp-modules/cache.json`, using module identifiers from `GET /modules`:

```json
{
  "version": 1,
  "modules": {
    "shodan": {
      "enabled": true,
      "ttl_seconds": 300,
      "max_entries": 128,
      "max_bytes": 16777216
    },
    "circl_passivedns": {
      "enabled": true,
      "ttl_seconds": 3600,
      "max_entries": 256,
      "max_bytes": 33554432
    },
    "virustotal": {
      "enabled": false
    }
  }
}
```

Start the service with:

```bash
misp-modules --cache-config /etc/misp-modules/cache.json
```

For systemd or containers, append this option to the existing startup command and
make the file readable by the service account. It can be used together with
`--module-config`; the two files have independent schemas. Cache settings are
server-local and are never taken from a query's `config` object.

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Explicitly enable caching for this module |
| `ttl_seconds` | `300` | Result lifetime, measured from successful execution |
| `max_entries` | `128` | Maximum retained results for this module |
| `max_bytes` | `16777216` | Maximum combined serialized response body bytes for this module (16 MiB) |

Limits must be positive integers; `enabled` must be a JSON boolean. Omitted
modules and modules without `"enabled": true` use the existing execution path.
Unknown fields, malformed JSON and invalid limits stop startup with a message
that does not include configuration values. The top-level fields must be exactly
`version` (integer `1`) and `modules` (an object). Module names must be nonempty
and must not begin with the reserved `type:` prefix.

Caching is restricted to expansion modules, including custom expansion modules.
Enabling it for a loaded action, import or export module stops startup. Entries
for unavailable modules are inert until those modules are installed. Select only
read-only lookups: some expansion modules submit samples, send notifications or
otherwise cause side effects, and caching those modules intentionally suppresses
repeated execution. No module is enabled automatically.

Restart to apply changes, empty the cache or reset cache counters. To disable the
feature, remove `--cache-config` and restart. There is no automatic file discovery,
reload or public cache administration endpoint.

## Matching and isolation

The dispatcher applies optional local module configuration defaults first. The
cache then matches the **entire effective request**, with object keys sorted
recursively. JSON whitespace and object key order do not affect matching. Array
order, module name, attribute UUID, event context, credential, service URL,
configuration and timeout all remain significant. Changing any of those values
causes a separate lookup.

This is deliberately conservative: two different MISP attributes containing the
same observable do not share a result if their UUIDs or other request fields
differ. Modules can embed those fields in their responses. Reusing a complete
response across those attributes could return the wrong references. Values are
not lowercased or otherwise normalized, and arbitrary fields cannot be excluded
from matching.

Cache keys are HMAC-SHA256 digests using a random, process-local secret. Raw
payloads and credentials are not retained as keys or exposed by metrics. Serialized
results are held as immutable bytes so subsequent calls cannot mutate them.
Results can contain sensitive information; protect access to the service and its
process memory as usual. Callers using identical effective credentials and request
context share results within that process; separate service instances remain
appropriate for separate trust boundaries.

## Execution, expiry and failures

An unexpired hit returns the same response body as the original execution. Hits
do not extend expiry. On a miss, the module executes normally; simultaneous
identical misses share that execution. Different requests and modules can execute
concurrently. This does not implement provider rate limiting or prevent queries
for different observables.

Successful non-null results, including empty result sets, are retained. Responses
with a nonempty top-level `error` or `errors` field, exceptions and serialization
failures are not retained. Concurrent waiters receive the same failure, and a
subsequent request retries normally. Results exceeding `max_bytes` are returned
normally without being stored or displacing existing entries.

Each HTTP request retains its existing timeout. A timed-out worker may continue
running, as before, and identical concurrent requests can still share it. Its
result is not stored if it completes after the originating request's deadline,
including time spent queued in the executor. The server-generated timeout response
is never cached.

Expired entries are removed on the next cache access or statistics read. When a
limit is reached, the least recently used results are evicted. Entry and byte
limits apply independently to each module. `max_bytes` counts response bodies;
Python object overhead and currently executing requests also consume memory.

The cache is process-local and disappears on restart. Multiple workers or service
replicas have independent caches and may each perform a lookup. Direct Python
calls to a module handler bypass the dispatcher and its cache. No outbound HTTP
client is patched; a saved module invocation can avoid zero, one or several
provider calls depending on the module.

## Monitor effectiveness

With caching enabled for a loaded expansion module, `GET /statistics` adds a
`cache.modules` object keyed by module identifier. It includes:

- `hits`: queries served from an unexpired result.
- `misses`: queries that started a module execution.
- `coalesced`: queries sharing an identical in-flight execution.
- `saved_queries`: `hits + coalesced`, the number of avoided module invocations.
- `stores`, `evictions`, `expired` and `skipped`: completed results stored, removed
  for capacity, removed for expiry, or not stored due to errors, null, size or deadline.
- `entries`, `response_bytes`, `in_flight` and the configured limits.

Unhandled exceptions and serialization failures remain visible in the existing
query error statistics; they are not counted in `skipped`. Cache `in_flight`
counts distinct ongoing executions and can include timed-out workers, while the
existing query `in_flight` counts HTTP queries still awaiting their outcome.
Existing query totals count every request, including cache hits and concurrent
waiters; they do not measure outbound provider calls. Cache counters contain no
payloads, results, keys or credentials, and reset on restart. Without any loaded
module explicitly enabled for caching, the statistics response has no `cache`
field. The optional fields are also documented in `/openapi.json`.
