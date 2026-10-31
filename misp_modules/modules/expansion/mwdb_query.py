import json
import re
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256", "sha512"], "format": "misp_standard"}
moduleconfig = ["mwdb_apikey", "mwdb_url"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "MWDB Query",
    "description": "Query an MWDB instance for an existing file by hash.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Looks up MD5, SHA-1, SHA-256 or SHA-512 using GET /file/{hash} with Bearer authentication."
        " Reuses the MWDB Submit configuration names mwdb_apikey and mwdb_url (the API base URL ending in /api/)."
        " Returns a file object, a sample link and an annotation containing MWDB tags, file type and upload time."
        " Tags remain contextual data rather than being applied as MISP tags. No samples are uploaded or downloaded."
    ),
    "references": ["https://mwdb.readthedocs.io/"],
    "input": "md5, sha1, sha256 or sha512 MISP attribute.",
    "output": "File metadata, MWDB context and a link to the sample.",
}
TIMEOUT = 30
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}


class ModuleError(ValueError):
    """A module error safe to return without credentials or response bodies."""


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-fA-F]{%d}" % HASH_LENGTHS[kind], value):
        raise ModuleError(f"Invalid {kind} hash.")
    return value.lower()


def _api_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ModuleError("Missing mwdb_url configuration.")
    value = value.strip().rstrip("/")
    parts = urlsplit(value)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.port == 0
        or not parts.path.endswith("/api")
    ):
        raise ModuleError(
            "mwdb_url must be an HTTP(S) API URL ending in /api/, without credentials, query or fragment."
        )
    return value + "/"


def _lookup(base, digest, apikey):
    try:
        response = requests.get(
            base + "file/" + digest,
            headers={"Authorization": "Bearer " + apikey},
            timeout=TIMEOUT,
            verify=True,
            allow_redirects=False,
        )
    except requests.RequestException:
        raise ModuleError("The MWDB request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ModuleError(f"MWDB returned HTTP {response.status_code}.")
    try:
        data = response.json()
    except ValueError:
        raise ModuleError("MWDB returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise ModuleError("MWDB returned an unexpected file response.")
    return data


def _enrich(event, attribute, data, base, digest):
    if not isinstance(data, dict) or data.get("type") != "file":
        raise ModuleError("MWDB returned an unexpected file response.")
    hashes = {kind: _hash(kind, data[kind]) for kind in HASH_LENGTHS if data.get(kind) is not None}
    identifier = _hash("sha256", data.get("id"))
    if hashes.get(attribute["type"]) != digest or hashes.get("sha256") != identifier:
        raise ModuleError("MWDB returned a different file hash.")
    obj = MISPObject("file")
    obj.comment = "File metadata from MWDB"
    for kind, value in hashes.items():
        obj.add_attribute(kind, value=value, to_ids=False)
    name = data.get("file_name")
    if name is not None:
        if not isinstance(name, str):
            raise ModuleError("MWDB returned an invalid filename.")
        if name:
            obj.add_attribute("filename", value=name, to_ids=False)
    size = data.get("file_size")
    if size is not None:
        if type(size) is not int or size < 0:
            raise ModuleError("MWDB returned an invalid file size.")
        obj.add_attribute("size-in-bytes", value=size, to_ids=False)
    obj.add_reference(attribute["uuid"], "related-to")
    event.add_object(obj)
    link = event.add_attribute(
        "link", value=base[:-4] + "file/" + identifier, to_ids=False, comment="Link to MWDB sample"
    )
    obj.add_reference(link.uuid, "related-to")
    tags = data.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(t, dict) or not isinstance(t.get("tag"), str) for t in tags):
        raise ModuleError("MWDB returned invalid tags.")
    context = {"tags": [t["tag"] for t in tags]}
    for key in ("file_type", "upload_time"):
        if data.get(key) is not None:
            if not isinstance(data[key], str):
                raise ModuleError("MWDB returned invalid file context.")
            context[key] = data[key]
    annotation = MISPObject("annotation")
    annotation.comment = "MWDB file context"
    annotation.add_attribute("text", value=json.dumps(context, sort_keys=True), to_ids=False, disable_correlation=True)
    annotation.add_reference(attribute["uuid"], "describes")
    annotation.add_reference(obj.uuid, "describes")
    event.add_object(annotation)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(k) for k in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        digest = _hash(attribute["type"], attribute["value"])
        config = request.get("config")
        if not isinstance(config, dict):
            raise ModuleError("Missing MWDB configuration.")
        apikey = config.get("mwdb_apikey")
        if not isinstance(apikey, str) or not apikey.strip() or any(c.isspace() for c in apikey):
            raise ModuleError("Missing or invalid mwdb_apikey configuration.")
        base = _api_url(config.get("mwdb_url"))
        event = MISPEvent()
        event.add_attribute(**attribute)
        data = _lookup(base, digest, apikey)
        if data is not None:
            _enrich(event, attribute, data, base, digest)
        result = json.loads(event.to_json())
        return {"results": {key: result.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, AttributeError):
        return {"error": "Invalid request or MWDB response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
