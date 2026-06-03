import base64
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
userConfig = {
    "timeout": {
        "type": "Integer",
        "message": "HTTP timeout in seconds",
        "default": 30,
    },
    "max_records": {
        "type": "Integer",
        "message": "Maximum number of JSON objects to import",
        "default": 1000,
    },
    "include_unmapped_attributes": {
        "type": "Boolean",
        "message": "Import recognised indicator values that could not be mapped to an object as standalone attributes",
        "default": True,
    },
}

mispattributes = {
    "inputSource": ["paste"],
    "output": ["MISP Format"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": (
        "Fetch a JSON file from an URL and generically map its records to the closest MISP object templates."
    ),
    "module-type": ["import"],
    "name": "Generic JSON Import",
    "logo": "",
    "requirements": ["requests", "PyMISP"],
    "features": (
        "The module accepts an HTTP(S) URL pointing to a JSON file, fetches it, walks the JSON structure, "
        "and compares discovered keys with the MISP object templates bundled with PyMISP. Best matching "
        "records are emitted as MISP objects in misp_standard format; recognised indicator values that do not "
        "fit an object can optionally be imported as standalone attributes."
    ),
    "references": ["https://github.com/MISP/misp-objects/tree/main/objects"],
    "input": "URL pointing to a JSON file",
    "output": "MISP objects and attributes",
}

moduleconfig = []

MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
MIN_OBJECT_SCORE = 5

_ALIAS_BY_TYPE = {
    "AS": {"as", "asn", "autonomoussystem", "autonomous_system"},
    "domain": {"domain", "domainname", "domain_name"},
    "email": {"email", "emailaddress", "email_address", "mail"},
    "email-dst": {"emaildst", "emailto", "dstemail", "destinationemail", "to"},
    "email-src": {"emailsrc", "emailfrom", "srcemail", "sourceemail", "from"},
    "filename": {"filename", "file_name", "name"},
    "hostname": {"hostname", "host", "fqdn"},
    "ip-dst": {"ip", "ipaddress", "ip_address", "ipdst", "dstip", "destinationip", "destination_ip"},
    "ip-src": {"ipsrc", "srcip", "sourceip", "source_ip"},
    "md5": {"md5", "md5hash", "hashmd5"},
    "port": {"port", "dstport", "srcport", "destinationport", "sourceport"},
    "sha1": {"sha1", "sha1hash", "hashsha1"},
    "sha224": {"sha224", "sha224hash"},
    "sha256": {"sha256", "sha256hash", "hashsha256"},
    "sha384": {"sha384", "sha384hash"},
    "sha512": {"sha512", "sha512hash", "hashsha512"},
    "url": {"url", "uri", "link", "href"},
}

_ALIAS_BY_RELATION = {
    "dst-port": {"dstport", "destinationport", "destination_port"},
    "ip-dst": {"ip", "ipaddress", "ip_address", "dstip", "destinationip", "destination_ip"},
    "ip-src": {"srcip", "sourceip", "source_ip"},
    "resource_path": {"path", "resourcepath", "resource_path", "urlpath", "url_path"},
    "src-port": {"srcport", "sourceport", "source_port"},
}

_HASH_TYPES = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,128}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        config = getPassedConfig(request)
        url = getUploadedData(request).strip()
        json_data = fetch_json(url, config["timeout"])
        event = MISPEvent()
        generateData(event, json_data, config)
        return {"results": json.loads(event.to_json())}
    except Exception as exception:
        return {"error": str(exception)}


def getUploadedData(request):
    if "data" in request:
        return base64.b64decode(request["data"]).decode("utf8")
    if "url" in request:
        return request["url"]
    raise ValueError("No URL provided")


def getPassedConfig(request):
    config = {key: value.get("default") for key, value in userConfig.items()}
    config.update(request.get("config") or {})
    config["timeout"] = max(1, int(config.get("timeout") or 30))
    config["max_records"] = max(1, int(config.get("max_records") or 1000))
    config["include_unmapped_attributes"] = _to_bool(config.get("include_unmapped_attributes", True))
    return config


def fetch_json(url, timeout):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("The input must be a valid HTTP(S) URL")

    response = requests.get(url, timeout=timeout, stream=True)
    response.raise_for_status()

    content = bytearray()
    for chunk in response.iter_content(chunk_size=65536):
        content.extend(chunk)
        if len(content) > MAX_DOWNLOAD_SIZE:
            raise ValueError("The remote JSON file is larger than the supported 20 MB limit")
    return json.loads(content.decode(response.encoding or "utf-8"))


def generateData(event, data, config):
    templates = load_object_templates()
    for _, record in iter_json_records(data, config["max_records"]):
        flattened = flatten_record(record)
        if not flattened:
            continue
        match = find_best_template(flattened, templates)
        mapped_keys = set()
        if match is not None:
            template_name, relation_matches = match
            misp_object = MISPObject(template_name)
            for key, relation, attribute_type, value in relation_matches:
                if add_object_attribute(misp_object, relation, attribute_type, value):
                    mapped_keys.add(key)
            if misp_object.Attribute:
                event.objects.append(misp_object)
        if config["include_unmapped_attributes"]:
            add_unmapped_attributes(event, flattened, mapped_keys)


def load_object_templates():
    objects_path = MISPObject("url").misp_objects_path
    templates = []
    for definition_path in sorted(Path(objects_path).glob("*/definition.json")):
        with definition_path.open("r", encoding="utf-8") as definition_file:
            definition = json.load(definition_file)
        attributes = definition.get("attributes") or {}
        if attributes:
            templates.append(
                {
                    "name": definition["name"],
                    "attributes": attributes,
                    "required": set(definition.get("requiredOneOf") or []),
                }
            )
    return templates


def iter_json_records(data, max_records):
    emitted = 0
    stack = [("root", data)]
    while stack and emitted < max_records:
        path, current = stack.pop()
        if isinstance(current, dict):
            if has_scalar_leaf(current):
                emitted += 1
                yield path, current
            for key, value in reversed(list(current.items())):
                if isinstance(value, (dict, list)):
                    stack.append((str(key), value))
        elif isinstance(current, list):
            for index, value in reversed(list(enumerate(current))):
                if isinstance(value, (dict, list)):
                    stack.append((f"{path}[{index}]", value))


def has_scalar_leaf(value):
    if isinstance(value, dict):
        return any(not isinstance(v, (dict, list)) and v is not None for v in value.values())
    return False


def flatten_record(record, prefix=""):
    flattened = []
    for key, value in record.items():
        name = f"{prefix}_{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.extend(flatten_record(value, name))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    flattened.extend(flatten_record(item, name))
                elif is_supported_scalar(item):
                    flattened.append((name, item))
        elif is_supported_scalar(value):
            flattened.append((name, value))
    return flattened


def find_best_template(flattened, templates):
    best = None
    for template in templates:
        score = 0
        matches = []
        used_relations = set()
        for key, value in flattened:
            relation_match = best_relation_for_key(key, value, template["attributes"], used_relations)
            if relation_match is None:
                continue
            relation, attribute_type, relation_score = relation_match
            score += relation_score
            matches.append((key, relation, attribute_type, value))
            used_relations.add(relation)
        if not matches:
            continue
        required_matches = template["required"].intersection(used_relations)
        if template["required"] and not required_matches:
            score -= 3
        else:
            score += len(required_matches)
        score += template_name_value_bonus(template["name"], matches)
        if score >= MIN_OBJECT_SCORE and (best is None or score > best[0]):
            best = (score, template["name"], matches)
    if best is None:
        return None
    return best[1], best[2]


def template_name_value_bonus(template_name, matches):
    normalized_template_name = normalize(template_name)
    normalized_keys = {normalize(key) for key, _, _, _ in matches}
    if normalized_template_name in normalized_keys:
        return 5

    template_tokens = {normalize(token) for token in re.split(r"[^A-Za-z0-9]+", template_name) if token}
    if len(template_tokens) < 2:
        return 0

    signal_tokens = set(normalized_keys)
    for key, _, _, value in matches:
        signal_tokens.update(normalize(token) for token in re.split(r"[^A-Za-z0-9]+", key) if token)
        signal_tokens.update(normalize(inferred_type) for inferred_type in infer_misp_types(value))
    return 4 if template_tokens.issubset(signal_tokens) else 0


def best_relation_for_key(key, value, attributes, used_relations):
    normalized_key = normalize(key)
    inferred_types = infer_misp_types(value)
    best = None
    for relation, definition in attributes.items():
        if relation in used_relations:
            continue
        attribute_type = definition.get("misp-attribute")
        score = 0
        if normalized_key == normalize(relation):
            score += 5
        elif normalized_key in {normalize(alias) for alias in _ALIAS_BY_RELATION.get(relation, set())}:
            score += 4
        elif attribute_type and normalized_key in {
            normalize(alias) for alias in _ALIAS_BY_TYPE.get(attribute_type, set())
        }:
            score += 3

        if attribute_type in inferred_types:
            score += 2
        elif inferred_types and attribute_type not in {"text", "comment"} and score == 0:
            continue

        if score and (best is None or score > best[2]):
            best = (relation, attribute_type, score)
    return best


def add_object_attribute(misp_object, relation, attribute_type, value):
    value = scalar_to_string(value)
    if not value:
        return False
    misp_object.add_attribute(relation, type=attribute_type, value=value)
    return True


def add_unmapped_attributes(event, flattened, mapped_keys):
    for key, value in flattened:
        if key in mapped_keys:
            continue
        inferred_types = infer_misp_types(value)
        if not inferred_types:
            continue
        attribute_type = sorted(inferred_types)[0]
        event.add_attribute(attribute_type, scalar_to_string(value), comment=f"Imported from JSON field: {key}")


def infer_misp_types(value):
    value = scalar_to_string(value)
    if not value:
        return set()
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return {"url"}
    if _EMAIL_RE.match(value):
        return {"email", "email-src", "email-dst"}
    if _IP_RE.match(value):
        return {"ip-dst", "ip-src"}
    if _DOMAIN_RE.match(value):
        return {"domain", "hostname"}
    if _HASH_RE.match(value) and len(value) in _HASH_TYPES:
        return {_HASH_TYPES[len(value)]}
    if value.isdigit() and 0 <= int(value) <= 65535:
        return {"port"}
    return set()


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def scalar_to_string(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value).strip()


def is_supported_scalar(value):
    return isinstance(value, (str, int, float, bool)) and value is not None


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def introspection():
    modulesetup = dict(mispattributes)
    modulesetup["userConfig"] = userConfig
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
