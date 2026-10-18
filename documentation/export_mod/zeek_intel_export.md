# Zeek Intel Export

`zeek_intel_export` converts supplied MISP event and object attributes into a Zeek
Intel Framework input file. It produces the native tab-separated ASCII format,
with a `#fields` header and these columns:

```text
indicator    indicator_type    meta.source    meta.desc    meta.url
```

The separators in the actual file are **single tab characters**, not spaces.
No Zeek connection, credentials or extra Python dependencies are required. Zeek's
standard ingestion path is a file on its manager, so this implementation is an
export module; deployment remains with your existing file distribution process.
It does not install policy, reload sensors or publish through a network service.

MISP also offers a built-in Bro/Zeek export. This module provides a standalone
misp-modules export with explicit validation, object traversal, deterministic
deduplication, escaped fields and provenance aggregation. It uses only Zeek's
built-in Intel fields and types; no JA3 or other extension package is assumed.

## Configuration

Enable **Zeek Intel Export** in MISP's export-module settings. Configure these
settings there, or supply them in `config` when calling `/query` directly:

| Setting | Default | Meaning |
| --- | --- | --- |
| `source` | `misp-modules` | Stable Zeek metadata source label, a non-empty string of at most 128 characters. Use distinct labels for independent feeds. |
| `misp_url` | Empty | Optional HTTPS MISP base URL, including an installation subpath if needed. No credentials, query or fragment. Adds an event link when the indicator has one unambiguous event UUID or numeric ID. |
| `include_non_ids` | `false` | Explicitly include non-IDS attributes. Deleted events, objects and attributes remain excluded. |

Booleans accept JSON booleans, integers 0/1 and strings `true`, `false`, `1`, `0`.
Empty settings use the documented defaults. Only supplied attributes are examined;
the module does not fetch additional data from MISP. Input can be a standard
`{"Event": {...}}` event, a bare event, a legacy envelope with collections alongside
`Event`, or a list of these events.

## Supported types

| MISP type | Zeek type | Conversion |
| --- | --- | --- |
| `ip-src`, `ip-dst` | `Intel::ADDR` or `Intel::SUBNET` | Validate IPv4/IPv6 and canonicalize addresses. CIDRs become canonical networks, including clearing host bits. IPv4-mapped IPv6 addresses/networks normalize to IPv4, matching Zeek's identity. Scoped IPv6 is excluded. |
| `domain`, `hostname` | `Intel::DOMAIN` | IDNA encode, lowercase, remove a trailing DNS dot and validate DNS labels and the 253-character normalized name limit. |
| `domain\|ip` | Domain plus address/subnet | Validate both components and emit two independent indicators. The original association is retained as provenance, rather than enforced as a conjunction. |
| `url` | `Intel::URL` | Require absolute HTTP(S), remove the fragment, decode request-target escapes once as bytes, and generate Zeek-compatible Host/port keys. Supply `/` for an empty path. Credentials and literal whitespace are excluded. |
| `email`, `email-src`, `email-dst`, `target-email` | `Intel::EMAIL` | Accept a bare address with an ASCII local part and valid IDNA domain. Display-name and quoted-local-part formats are excluded. |
| `filename`, `email-attachment`, `attachment` | `Intel::FILE_NAME` | Emit the filename, with characters escaped for the ASCII reader. Binary attachment contents are not included. |
| `md5`, `sha1`, `sha256`, `sha512` | `Intel::FILE_HASH` | Validate hexadecimal length and lowercase. |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `filename\|sha512`, `malware-sample` | `Intel::FILE_HASH` | Emit only the hash component. Split at the last pipe so filenames may contain pipes. No sample data is exported. |
| `x509-fingerprint-sha1` | `Intel::CERT_HASH` | Validate a SHA-1 fingerprint; accept plain hex or colon-separated octets and emit lowercase plain hex. |
| `ssh-fingerprint` | `Intel::PUBKEY_HASH` | Accept an MD5 fingerprint in plain hex or colon-separated octets, optionally prefixed `MD5:`, and emit lowercase colon-separated octets. SHA-256 SSH fingerprints are excluded. |

Other types, including port-qualified composites, fuzzy/import hashes, user-agent
strings, JA3 and SHA-256 certificate fingerprints, are skipped. Port constraints
are not silently discarded. Unsupported and malformed attributes have separate
skipped counts. Invalid supported values do not prevent other eligible values
from being exported; malformed containers or configuration return an error.

Zeek's Intel string store matches case-insensitively. This module folds ASCII
letters in indicator keys to lowercase and merges matching keys so their common
source label cannot overwrite another attribute's metadata. This includes URL
paths, filenames and email local parts: Zeek Intel does not provide case-sensitive
matching for them. Non-ASCII bytes are preserved, and original MISP values remain
in the provenance. This is not a case-sensitive URL or filename matching engine.

URL keys follow Zeek's HTTP analyzer and `HTTP::build_url` observer. Percent escapes
in the path and query are decoded once as bytes before matching; `+` remains a
literal plus. For example, `http://example.org/a%2Fb?x=%41` becomes
`example.org/a/b?x=a`. Encoded `%25` is not recursively decoded. A literal fragment
is removed before decoding, so an encoded `%23` remains part of the request target.
An empty query delimiter (`/a?`) is retained. Zeek's legacy `%uHHHH` and doubled
percent handling are also supported. If the decoded target contains `://`, Zeek's
helper returns that target without a Host prefix; the exporter does the same.

Zeek appends the responder port when it differs from 80, including when the Host
header already contains a port. A URL such as `http://example.org:8080/a` therefore
emits both `example.org:8080/a` and `example.org:8080:8080/a`, covering Host headers
without and with the port. Explicit port 80 similarly emits the Host forms with
and without `:80`. The responder port is inferred from the URL: 80 for HTTP and
443 for HTTPS when omitted. Consequently, one URL attribute can produce multiple
rows, each retaining the same provenance. Distinct decoded keys are deduplicated.

TLS normally hides HTTPS paths; loading an HTTPS-derived URL does not make that
path observable on encrypted traffic. Reverse proxies, rewritten Host headers or
custom observers may report different strings; compare those observations with
your feed when configuring those deployments.

## Escaping and provenance

The file is ASCII, with non-ASCII bytes, controls, backslashes and `#` escaped
as `\xHH`. Zeek's ASCII reader restores the bytes. Literal `-` and `(empty)` strings
are escaped so they do not conflict with reader markers. Tabs/newlines in filenames
and metadata cannot create new columns, records or header directives. Optional
`meta.url` values use Zeek's unset marker `-`. Percent-encoded URL bytes that are
not valid UTF-8 are preserved in the feed without replacement. The API's display
of such keys uses backslash escapes; the base64 file contains the exact native key.

Each unique `(Intel type, canonical indicator)` appears once. `meta.source` is the
configured namespace. `meta.desc` is a JSON list of all contributing MISP event,
attribute and object references, MISP types and original values. References and
rows are sorted for deterministic output. `meta.url` points to the event only when
all references identify the same valid event; otherwise it is unset.

Event titles, comments, tags and binary data are not copied. Provenance can still
identify MISP events and contain original indicator values, so apply the event's
sharing and handling policy when selecting input and distributing the feed.
Existing `file`, `domain-ip` and `x509` object templates suffice; no new objects are
required. Object attributes use the same supported-type rules as event attributes.

## API example

POST to the misp-modules `/query` endpoint:

```json
{
  "module": "zeek_intel_export",
  "config": {
    "source": "MISP production",
    "misp_url": "https://misp.example"
  },
  "data": [{
    "Event": {
      "uuid": "f1ef0409-c80a-4012-b401-b7d1050f4ed4",
      "Attribute": [{
        "uuid": "aa09819b-f2d8-4661-83ea-d4897cafebc8",
        "type": "domain",
        "value": "EXAMPLE.org.",
        "to_ids": true
      }]
    }
  }]
}
```

The response contains `response: []` and base64-encoded file contents in `data`.
Decode that field and save it as a `.intel` file. An empty selection produces a
valid header-only feed. The `summary` field contains row count and skipped counts;
`sources` contains the canonical indicators and their contributing references.
Warnings explain skipped attributes. MISP's normal download returns the file and
may not display these additional response fields.

## Zeek setup and deployment

Add this to the manager's `local.zeek`, using your deployed file path:

```zeek
@load base/frameworks/intel
@load frameworks/intel/seen

redef Intel::read_files += { "/opt/zeek/share/zeek/site/misp.intel" };
```

`frameworks/intel/seen` loads the standard observation scripts, including the file
Intel types, so observed data can be checked against the feed. Configure and
deploy the policy through your normal Zeek administration. For a cluster, the
feed file is needed on the manager; Zeek distributes Intel state to workers.

Install updates **atomically**: write a complete new file beside the destination,
set the appropriate permissions, and rename it over the old file on the same
filesystem. Do not stream partial output into the live feed. Zeek's input reader
detects file changes and rereads the feed. Use a distinct `source` namespace for
each independently maintained feed: reusing a source for the same indicator in
separate files can replace its metadata.

Matching observations produce `intel.log` entries. A loaded indicator alone does
not guarantee a traffic match: analyzers and observation scripts must report it.
Default address observations cover established TCP connections; additional policy
is needed for other connection classes. File hashes require the corresponding
hash analyzers; SHA-512 in particular needs a custom observer/analyzer. Certificate
and SSH fingerprints likewise depend on the applicable protocol/file analysis.
The feed does not enable analyzers, create notices or enforce blocking. It omits
extension-only fields such as `meta.do_notice` and per-item expiry metadata.

### Withdrawal and expiry

Deleting a MISP attribute or removing a row from an updated feed does **not**
automatically withdraw the previously inserted indicator. Zeek's standard Intel
input handler inserts reread items; it does not reconcile absent rows. The default
`Intel::item_expiration` is disabled, and changing a feed's `source` can leave old
metadata behind. Plan withdrawal through your Zeek policy, using explicit Intel
removal, a configured expiration interval with an appropriate `Intel::item_expired`
hook, or a controlled restart with the intended complete feeds. This module emits
no removal instructions and does not set an expiry time.

## Validation

Tests cover supported mappings, objects, case-insensitive deduplication, provenance,
escaping, malformed input and the module server's discovery/query endpoints.
Optional native tests load the exported file into Zeek, exercise the real Intel
matcher, and replay HTTP packet captures through the standard URL observer. Set
`ZEEK` to an installed Zeek executable (or place `zeek` on PATH) to run them; they
are skipped when no runtime is available. Native validation was performed with
Zeek 8.0.5, including UTF-8, control characters, reader markers and
literal backslash escape sequences. No running sensor was changed.

References: [Intel Framework](https://docs.zeek.org/en/current/frameworks/intel.html),
[native Intel types](https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html),
[ASCII reader](https://docs.zeek.org/en/current/scripts/base/frameworks/input/readers/ascii.zeek.html),
and [Intel file loading and atomic updates](https://docs.zeek.org/en/current/scripts/base/frameworks/intel/input.zeek.html).
