# Wazuh CDB export

`wazuh_cdb_export` exports one type of MISP indicators as a Wazuh CDB **source** list.
The downloadable UTF-8 text contains sorted, unique `key:` lines, without a header.
It is not the compiled `.cdb` database. No Wazuh connection or credentials are required.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `indicator_type` | `ipv4` | `ipv4`, `ipv6`, `domain`, `md5`, `sha1`, `sha256` or `sha512` |
| `include_non_ids` | `false` | Include attributes without `to_ids`; deleted data is always excluded |

Supply one event or a list of events in `data`. Standard `{"Event": {...}}`, bare events,
and legacy exports with `Attribute`/`Object` next to `Event` are accepted. Attributes
inside objects are included. Existing `file` and `domain-ip` templates work without changes.

IP addresses are normalized and divided into IPv4 and IPv6 lists. Domains and hostnames
are lowercased, converted to IDNA ASCII and stripped of a trailing dot. Hashes are
validated and lowercased. `filename|md5`, `filename|sha1`, `filename|sha256`,
`filename|sha512` and `malware-sample` provide their hash component; `domain|ip`
provides the component matching the selected type.

URLs are excluded: Wazuh's CDB upload validator restricts colon-containing quoted
keys, so ordinary URLs cannot be uploaded reliably. CIDR networks, ports and other
attribute types are also excluded. Malformed and inapplicable attributes are counted
in `summary.skipped`. The response contains provenance in `sources` and warnings
outside the downloaded file. Empty lists, more than 100,000 unique values, or a file
larger than 32 MiB return an error. The byte limit accommodates 100,000 long domain
names as well as file hashes. When uploading large files, raise Wazuh's API
`max_upload_size` (10 MiB by default) and any proxy request limits to accommodate
the file; the connector does not change those server settings.

## Example

POST this JSON to the module server's `/query` endpoint:

```json
{
  "module": "wazuh_cdb_export",
  "config": {"indicator_type": "ipv4"},
  "data": [{"Event": {"uuid": "event-1", "Attribute": [
    {"type": "ip-dst", "value": "192.0.2.1", "to_ids": true, "uuid": "attribute-1"}
  ]}}]
}
```

Decode the response's base64 `data` to obtain:

```text
192.0.2.1:
```

An IPv6 list uses quoted keys, for example `"2001:db8::1":`. IPv6 keys use exact
string matching; the decoded field must use the same normalized spelling. Do not
use Wazuh's IPv4 address lookup modes for this list.

## Activate the list in Wazuh

Save the decoded source as `/var/ossec/etc/lists/misp-ipv4` (the MISP download has
a `.txt` extension; rename it). Alternatively use the
[Wazuh CDB Publish action](../action_mod/wazuh_cdb_publish.md).

Register it in the existing `<ruleset>` section of `/var/ossec/etc/ossec.conf`:

```xml
<list>etc/lists/misp-ipv4</list>
```

Add a local detection rule appropriate to the decoder and event source. This example
matches an IPv4 `srcip` decoded from an event; choose an unused local rule ID:

```xml
<group name="misp,">
  <rule id="100500" level="10">
    <list field="srcip" lookup="address_match_key">etc/lists/misp-ipv4</list>
    <description>Source IP matches MISP threat intelligence</description>
  </rule>
</group>
```

Use `lookup="match_key"` and the appropriate decoded field for domains or hashes.
Matching is against the decoded field; a domain list does not resolve DNS names,
automatically match subdomains or normalize the incoming field.

Validate the local rules and request an analysisd ruleset reload through the Wazuh
API to load the list; a full Wazuh manager restart is not mandatory:

- Single manager or local node: `PUT /manager/analysisd/reload`.
- Cluster: `PUT /cluster/analysisd/reload` (all nodes by default).

The [publish action](../action_mod/wazuh_cdb_publish.md) can request the appropriate
reload after uploading using `reload=manager` or `reload=cluster`. Register the list
and detection rule first, and follow your cluster's ruleset synchronization procedure.
A reload acknowledgement indicates that the request was sent; check analysisd logs
for completion and any configuration errors. An export or upload alone does not
activate detection. A full manager restart remains an alternative when needed by
your deployment or Wazuh version.

References:

- [Wazuh CDB lists and rule lookup modes](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)
- [Wazuh 4.14.1 CDB upload validator](https://github.com/wazuh/wazuh/blob/v4.14.1/framework/wazuh/core/cdb_list.py)
- [Wazuh server API, including analysisd reload endpoints](https://documentation.wazuh.com/current/user-manual/api/reference.html)
