# VirusTotal Graph export

`vt_graph` exports selected MISP events through the official `vt-graph-api`
Python SDK. The integration uses VirusTotal API v3. The compatibility review was
performed against the current Graph create/update/object documentation and SDK
2.2.0; the existing SDK already uses the v3 routes and payload format.

## Configuration

| Setting | Meaning |
| --- | --- |
| `vt_api_key` | Required VirusTotal API key. The SDK sends it in `x-apikey`. |
| `private` | New graph visibility; default false (public). Private graphs require an appropriate subscription and available quota. |
| `fetch_information` | Fetch node metadata; default false. |
| `fetch_vt_enterprise` | Permit the SDK's additional Intelligence lookups when resolving identifiers; default false. |
| `expand_one_level` | Expand the graph one level through VT relationships; default false. Can consume substantial API quota. |
| `user_editors`, `user_viewers` | Comma-separated VT user identifiers for new graphs. |
| `group_editors`, `group_viewers` | Comma-separated VT group identifiers for new graphs. |

Boolean settings accept JSON booleans, 0/1, and case-insensitive `true`/`false`
or `0`/`1` strings. Missing, null and empty settings mean false. Other values
return an error before calling VT. Collaborator identifiers are trimmed and
deduplicated, and empty CSV entries are ignored.

One-level expansion considers only the native VT nodes present before expansion
that have available relationships. Custom nodes and native nodes without
relationships are preserved without expansion. Newly discovered nodes are added
to the graph and are not expanded again in that same invocation.

Export creates or updates a remote graph; it is not a dry run. A new graph is
public unless `private` is explicitly true. For an existing graph, its loaded
visibility and collaborators are preserved rather than replaced by the new-graph
configuration. The API key must have edit access to save an existing graph.

## Event input and node mapping

`data` accepts a non-empty list of events or a single event. Each event can be:

- A flat object containing `Attribute` and/or `Object` collections.
- A wrapper with those collections inside `Event`.
- A core export with selected collections beside the `Event` metadata. Explicit
  outer collections take precedence, including empty ones.

Supported active attributes are collected from the event and its active objects.
Deleted attributes/objects are skipped. The complete batch is validated before
SDK lookups, expansion or graph writes. Each event must contain at least one
supported active attribute; an empty selection does not fall back to a broader
event. Missing attribute categories are accepted.

| MISP types | Graph representation |
| --- | --- |
| `domain`, `hostname` | Domain node. |
| `ip-src`, `ip-dst` | IP address node, including IPv6 values. |
| `md5`, `sha1`, `sha256` | File node. Hashes are validated and normalized to lowercase. The SDK resolves MD5/SHA-1 to SHA-256 when VT knows the file. |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256` | File node with the filename as its label. Split at the **last** pipe, preserving pipes in filenames (also fixes the defect described in PR #893). |
| `url` | URL node, using the SDK's URL ID resolution. |
| `filename` | Custom `filename` node; a filename alone does not identify a specific VT file and is not searched as one. |
| `target-user`, `target-email` | Custom `victim`/`email` nodes. These can be the first or only nodes. |

Unsupported types are ignored. Supported attributes require non-empty string
values. Duplicate nodes, including hash aliases resolved to the same VT file,
are skipped during insertion to avoid self-links. Relationship rules connect
nodes according to their order and MISP category; these inferred links are not
evidence of a relationship confirmed by VT.

The SDK can make requests even when `fetch_information` is false: resolving an
MD5/SHA-1 uses file lookups, and resolving a raw URL uses **`POST /api/v3/urls`**,
which submits it for analysis. Public/private graph visibility does not change
the semantics of URL analysis submission. The integration retains this SDK
behavior; false disables metadata fetching, not every request beyond graph
creation. Expansion makes additional relationship requests. No sample binaries
or attachment data are uploaded by this exporter.

## Existing graphs and output

An event-level `link` attribute can identify an existing graph using
`https://www.virustotal.com/graph/<id>` or `/gui/graph/<id>`. IDs must be `g`
followed by 64 lowercase hex characters. Query/fragment components are not part
of the graph ID. For multiple valid links, the largest numeric MISP attribute ID
wins; without numeric IDs, the last input link wins. Malformed or unrelated
links are ignored.

The SDK loads an existing graph with `GET /api/v3/graphs/{id}`, adds missing
nodes and saves with `PATCH /api/v3/graphs/{id}`. Without a graph link, it creates
one using `POST /api/v3/graphs`. The native payload has `data.type: graph` and
`data.attributes` containing `graph_data`, boolean `private`, `nodes` and `links`.
Node `entity_id` values and link source/target IDs come from the SDK. New-graph
collaborators use the v3 viewer/editor endpoints.

The module returns a base64-encoded text file containing one SDK-generated graph
URL per exported event, preserving the existing export response format.
Load/create/save/collaborator failures return a sanitized error without exposing
the API key or raw backend response. A failed load never creates a replacement
graph. There are no module-level retries. A later save or collaborator failure
can occur after a graph has already been created; inspect existing graphs before
retrying an unsuccessful export.

## References

- [Create graphs](https://docs.virustotal.com/reference/create-graphs)
- [Update a graph](https://docs.virustotal.com/reference/graphs-update)
- [Graph object](https://docs.virustotal.com/reference/graph-object)
- [URL identifiers](https://docs.virustotal.com/reference/url)
- [Graph management and visibility](https://docs.virustotal.com/docs/graph-management)
- [Official Python SDK](https://github.com/VirusTotal/vt-graph-api)
- [Related filename-splitting fix, PR #893](https://github.com/MISP/misp-modules/pull/893)
