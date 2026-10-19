import json
from ipaddress import ip_address
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from pymisp import MISPEvent

from . import check_input_attribute, standard_error_message

HASH_TYPES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
VALUE_TYPES = {
    "domain": "Domain-Name",
    "hostname": "Hostname",
    "url": "Url",
    "email-src": "Email-Addr",
    "email-dst": "Email-Addr",
}
mispattributes = {
    "input": [*VALUE_TYPES, "ip-src", "ip-dst", *HASH_TYPES, *(f"filename|{kind}" for kind in HASH_TYPES)],
    "output": ["text", "link"],
    "format": "misp_standard",
}
moduleconfig = ["url", "token", "max_results", "timeout"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "OpenCTI Lookup",
    "description": "Query an OpenCTI instance for exact observable matches and their context and source references.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "An OpenCTI instance and an API token with knowledge read access."],
    "features": (
        "Read-only GraphQL lookup using OpenCTI's FilterGroup API (OpenCTI 5.12 or later). Set url to the instance"
        " base URL (optionally ending in /graphql) and token to its API token. max_results defaults to 20 (1-100)"
        " and timeout to 30 seconds (1-120). Domains and IPs are normalized; file hashes, including filename|hash"
        " attributes, are matched against the specific hash algorithm. Results contain text context (description,"
        " score, author, labels, markings and timestamps), links to OpenCTI and external references. Imported"
        " attributes have to_ids=false; TLP markings are retained as tags and other markings as text. Custom"
        " markings and OpenCTI access controls are not translated into MISP sharing restrictions. No data is"
        " written to OpenCTI and no relationship traversal or synchronization is performed. A result cap notice"
        " is returned when more matches are available. No matches produce an empty Attribute list."
    ),
    "references": ["https://docs.opencti.io/latest/reference/api/"],
    "input": "A domain, hostname, IP address, URL, email address or file hash (including filename|hash).",
    "output": "MISP text and link attributes with provenance and TLP tags.",
}

# Easter egg, with a wink: misp-modules queries pseudo-open source projects too.
# Interoperability is a feature; the joke stays out of the intelligence.

QUERY = """
query MispOpenCTILookup($types: [String], $filters: FilterGroup, $first: Int) {
  stixCyberObservables(types: $types, filters: $filters, first: $first) {
    pageInfo { hasNextPage }
    edges {
      node {
        id
        standard_id
        entity_type
        observable_value
        x_opencti_description
        x_opencti_score
        created_at
        updated_at
        createdBy { name }
        objectLabel { value }
        objectMarking { definition_type definition }
        externalReferences(first: 20) {
          edges { node { source_name url external_id description } }
        }
        ... on StixFile { hashes { algorithm hash } }
      }
    }
  }
}
"""
LEGACY_QUERY = QUERY.replace("objectLabel { value }", "objectLabel { edges { node { value } } }").replace(
    "objectMarking { definition_type definition }", "objectMarking { edges { node { definition_type definition } } }"
)


def _endpoint(value):
    if not isinstance(value, str):
        raise ValueError("Set url to the OpenCTI instance URL.")
    try:
        parts = urlsplit(value.strip())
        valid = parts.scheme in ("http", "https") and parts.hostname and parts.port != 0
    except ValueError:
        valid = False
    if not valid or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("The OpenCTI url must be an HTTP(S) URL without credentials, a query or a fragment.")
    path = parts.path.rstrip("/")
    if path.endswith("/graphql"):
        path = path[: -len("/graphql")]
    base = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return base, base + "/graphql"


def _integer(config, name, default, maximum):
    raw = config.get(name)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool) or not str(raw).isdigit() or not 1 <= int(raw) <= maximum:
        raise ValueError(f"{name} must be an integer between 1 and {maximum}.")
    return int(raw)


def _lookup_spec(attribute):
    kind, value = attribute["type"], attribute["value"].strip()
    if "|" in kind:
        kind = kind.split("|", 1)[1]
        filename, separator, value = value.rpartition("|")
        if not filename or not separator:
            raise ValueError("A filename|hash attribute must contain both a filename and a hash.")
    if kind in HASH_TYPES:
        value = value.strip().lower()
        size = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[kind]
        if len(value) != size or any(character not in "0123456789abcdef" for character in value):
            raise ValueError(f"Invalid {kind} hash.")
        return "StixFile", f"hashes.{HASH_TYPES[kind]}", value, kind
    if kind in ("ip-src", "ip-dst"):
        try:
            address = ip_address(value)
        except ValueError:
            raise ValueError("Invalid IP address.") from None
        return f"IPv{address.version}-Addr", "value", str(address), kind
    if kind in ("domain", "hostname"):
        value = value.rstrip(".").lower()
    if not value:
        raise ValueError("The attribute value is empty.")
    return VALUE_TYPES[kind], "value", value, kind


def _matches(node, entity_type, value, kind):
    if node.get("entity_type") != entity_type:
        return False
    if kind in HASH_TYPES:
        return any(
            item.get("algorithm") == HASH_TYPES[kind] and str(item.get("hash", "")).lower() == value
            for item in node.get("hashes") or []
            if isinstance(item, dict)
        )
    returned = str(node.get("observable_value", ""))
    if kind in ("domain", "hostname"):
        returned = returned.rstrip(".").lower()
    elif kind in ("ip-src", "ip-dst"):
        try:
            returned = str(ip_address(returned))
        except ValueError:
            return False
    return returned == value


def _query(endpoint, token, variables, timeout, legacy=False):
    try:
        response = requests.post(
            endpoint,
            json={"query": LEGACY_QUERY if legacy else QUERY, "variables": variables},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        return None, "The OpenCTI request timed out."
    except requests.exceptions.RequestException:
        return None, "The OpenCTI request failed. Check connectivity and TLS configuration."
    if response.status_code in (401, 403):
        return None, f"OpenCTI denied access (HTTP {response.status_code}). Check the token and knowledge read access."
    if response.status_code == 429:
        return None, "OpenCTI rate limit reached (HTTP 429)."
    if 300 <= response.status_code < 400:
        return None, "OpenCTI returned a redirect. Configure the final instance URL."
    if response.status_code != 200:
        return None, f"OpenCTI returned HTTP {response.status_code}."
    try:
        payload = response.json()
    except ValueError:
        return None, "OpenCTI returned invalid JSON."
    if not isinstance(payload, dict):
        return None, "OpenCTI returned an unexpected response."
    # Do not echo server errors or exception strings: these can contain secrets.
    if payload.get("errors"):
        errors = payload["errors"]
        if (
            not legacy
            and isinstance(errors, list)
            and any(
                isinstance(error, dict)
                and isinstance(error.get("message"), str)
                and "Cannot query field" in error["message"]
                and any(name in error["message"] for name in ("LabelConnection", "MarkingDefinitionConnection"))
                for error in errors
            )
        ):
            return _query(endpoint, token, variables, timeout, legacy=True)
        return None, "OpenCTI returned GraphQL errors. Check API compatibility, token permissions and server logs."
    try:
        connection = payload["data"]["stixCyberObservables"]
        edges = connection["edges"]
        has_next = connection["pageInfo"]["hasNextPage"]
        if not isinstance(edges, list) or not isinstance(has_next, bool):
            raise ValueError
        if any(
            not isinstance(edge["node"], dict) or not isinstance(edge["node"].get("id"), str) or not edge["node"]["id"]
            for edge in edges
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return None, "OpenCTI returned an unexpected response."
    return connection, None


def _nodes(value):
    if isinstance(value, dict):
        return [edge["node"] for edge in value["edges"]]
    return value or []


def _add_context(event, node, base, attribute):
    source = base + "/dashboard/observations/observables/" + quote(str(node["id"]), safe="")
    lines = [f"OpenCTI {node['entity_type']}: {node.get('observable_value', '')}", f"Source: {source}"]
    for field, title in (
        ("standard_id", "STIX ID"),
        ("x_opencti_description", "Description"),
        ("x_opencti_score", "Score"),
        ("created_at", "Created"),
        ("updated_at", "Updated"),
    ):
        if node.get(field) is not None:
            lines.append(f"{title}: {node[field]}")
    if node.get("createdBy"):
        lines.append(f"Author: {node['createdBy']['name']}")
    labels = [label["value"] for label in _nodes(node.get("objectLabel"))]
    if labels:
        lines.append("Labels: " + ", ".join(labels))
    tags = []
    for marking in _nodes(node.get("objectMarking")):
        definition = marking.get("definition") or ""
        lines.append(f"Marking ({marking.get('definition_type')}): {definition}")
        if str(marking.get("definition_type", "")).upper() == "TLP":
            level = definition.upper().removeprefix("TLP:")
            if level in ("WHITE", "CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"):
                tags.append("tlp:" + level.lower())

    common = {"to_ids": False, "disable_correlation": True, "comment": f"OpenCTI context for {attribute['value']}"}

    def add(kind, value):
        result = event.add_attribute(type=kind, value=value, **common)
        for tag in tags:
            result.add_tag(tag)

    links = {source}
    for edge in (node.get("externalReferences") or {}).get("edges") or []:
        reference = edge["node"]
        details = [
            str(reference[key]) for key in ("source_name", "external_id", "description", "url") if reference.get(key)
        ]
        if details:
            lines.append("Reference: " + " | ".join(details))
        url = reference.get("url")
        if isinstance(url, str) and urlsplit(url).scheme in ("http", "https"):
            links.add(url)
    add("text", "\n".join(lines))
    for link in sorted(links):
        add("link", link)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and a UUID."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    if not isinstance(attribute["value"], str):
        return {"error": "The attribute value must be a string."}
    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "The module config must be an object."}
    token = config.get("token")
    if not isinstance(token, str) or not token.strip() or "\n" in token or "\r" in token:
        return {"error": "An OpenCTI API token is required (set token in the module config)."}
    try:
        base, endpoint = _endpoint(config.get("url"))
        limit = _integer(config, "max_results", 20, 100)
        timeout = _integer(config, "timeout", 30, 120)
        entity_type, key, value, kind = _lookup_spec(attribute)
    except ValueError as error:
        return {"error": str(error)}
    variables = {
        "types": [entity_type],
        "first": limit,
        "filters": {
            "mode": "and",
            "filters": [{"key": [key], "values": [value], "operator": "eq", "mode": "or"}],
            "filterGroups": [],
        },
    }
    connection, error = _query(endpoint, token.strip(), variables, timeout)
    if error:
        return {"error": error}
    event, seen = MISPEvent(), set()
    try:
        for edge in connection["edges"][:limit]:
            node = edge["node"]
            if node["id"] not in seen and _matches(node, entity_type, value, kind):
                _add_context(event, node, base, attribute)
                seen.add(node["id"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"error": "OpenCTI returned an unexpected observable format."}
    if connection["pageInfo"]["hasNextPage"]:
        event.add_attribute(
            type="text",
            value=f"OpenCTI lookup limited to {limit} results. More matches are available in the OpenCTI instance.",
            to_ids=False,
            disable_correlation=True,
        )
    return {"results": {"Attribute": json.loads(event.to_json()).get("Attribute", [])}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
