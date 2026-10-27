import base64
import io
import json
import runpy
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from mwdblib import MWDB
from mwdblib.exc import MWDBError
from pymisp import PyMISP
from pymisp.exceptions import PyMISPError
from requests.exceptions import RequestException

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment", "malware-sample"], "output": ["link"]}
moduleinfo = {
    "version": "2",
    "author": "Koen Van Impe",
    "description": "Module to push malware samples to a MWDB instance",
    "module-type": ["expansion"],
    "name": "MWDB Submit",
    "logo": "",
    "requirements": [
        "mwdblib>=4.0.0 and MWDB Core>=2.6.0",
        "Optional keys.py file for MISP event and attribute tags",
        "Optional MWDB attribute key configured in mwdb_misp_attribute",
    ],
    "features": (
        "Uploads an attachment or unpacked MISP malware sample to MWDB using an API key."
        " Optionally forwards event and attribute tags, the attribute comment and the MISP event ID."
        " Returns a link to the uploaded sample. mwdb_url accepts an instance URL or an API URL ending in /api/."
        " Boolean settings accept true/false, yes/no, on/off and 1/0."
        " mwdb_public defaults to true for compatibility; set it to false to use normal instance sharing."
        " See documentation/expansion/mwdb.md for configuration."
    ),
    "references": ["https://mwdb.readthedocs.io/en/latest/user-guide/8-REST-and-mwdblib.html"],
    "input": "Attachment or malware sample",
    "output": "Link attribute pointing to the uploaded MWDB sample",
}
moduleconfig = [
    "mwdb_apikey",
    "mwdb_url",
    "mwdb_misp_attribute",
    "mwdb_public",
    "include_tags_event",
    "include_tags_attribute",
]
pymisp_keys_file = "/var/www/MISP/PyMISP/"
mwdb_public_default = True


class ModuleError(ValueError):
    """A validation error safe to return to the caller."""


def _boolean(config, name, default=False):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, int)):
        value = str(value).strip().lower()
        if value in ("1", "true", "yes", "on"):
            return True
        if value in ("0", "false", "no", "off"):
            return False
    raise ModuleError(f"{name} must be a boolean (true/false).")


def _urls(value):
    if not isinstance(value, str) or not value.strip():
        raise ModuleError("Missing MWDB server URL.")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        raise ModuleError("Invalid MWDB server URL.") from None
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and port == 0)
        or any(character.isspace() for character in value.strip())
    ):
        raise ModuleError("MWDB URL must be an HTTP(S) instance or API URL without credentials, query or fragment.")
    path = parsed.path.rstrip("/")
    if path.endswith("/api"):
        path = path[:-4]
    base = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    return base + "/api/", base + "/file/"


def _sample(request):
    kinds = [kind for kind in mispattributes["input"] if kind in request]
    if len(kinds) != 1:
        raise ModuleError("Supply exactly one malware sample or attachment.")
    kind = kinds[0]
    filename = request[kind]
    if not isinstance(filename, str) or not filename.strip():
        raise ModuleError("A sample filename is required.")
    if not isinstance(request.get("data"), str) or not request["data"]:
        raise ModuleError("Base64-encoded sample data is required.")
    try:
        data = base64.b64decode(request["data"], validate=True)
        if kind == "malware-sample":
            filename = filename.split("|", 1)[0]
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                # MISP archives may contain the original filename before the binary.
                members = [
                    item
                    for item in archive.infolist()
                    if not item.is_dir() and not item.filename.endswith(".filename.txt")
                ]
                if len(members) != 1:
                    raise ModuleError("A malware-sample archive must contain exactly one sample.")
                data = archive.read(members[0], pwd=b"infected")
    except ModuleError:
        raise
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error):
        raise ModuleError("Unable to decode or unpack submitted sample data.") from None
    if not filename.strip():
        raise ModuleError("A sample filename is required.")
    return filename, data


def _metadata(request, include_event, include_attribute):
    comments = [f"MISP attribute {request['attribute_uuid']}"] if request.get("attribute_uuid") else []
    if not (include_event or include_attribute):
        return [], comments
    if include_event and not request.get("event_id"):
        raise ModuleError("event_id is required to include event tags.")
    if include_attribute and not request.get("attribute_uuid"):
        raise ModuleError("attribute_uuid is required to include attribute tags.")
    try:
        # Load the legacy configuration without changing the process-wide import path.
        keys = runpy.run_path(str(Path(pymisp_keys_file) / "keys.py"))
        misp = PyMISP(keys["misp_url"], keys["misp_key"], keys["misp_verifycert"], False)
        tags = []
        if include_event:
            result = misp.get_event(request["event_id"])
            if not isinstance(result, dict) or not isinstance(result.get("Event"), dict):
                raise ModuleError("Unable to fetch MISP event metadata.")
            event = result["Event"]
            tags.extend(event.get("Tag") or [])
            if event.get("info"):
                comments.append(f"Fetched from event {request['event_id']} - {event['info']}")
        if include_attribute:
            result = misp.get_attribute(request["attribute_uuid"])
            if not isinstance(result, dict) or not isinstance(result.get("Attribute"), dict):
                raise ModuleError("Unable to fetch MISP attribute metadata.")
            attribute = result["Attribute"]
            tags.extend(attribute.get("Tag") or [])
            if attribute.get("comment"):
                comments[0] = attribute["comment"]
    except (OSError, ImportError, KeyError, SyntaxError, PyMISPError, RequestException):
        raise ModuleError("Unable to read MISP metadata; check the PyMISP keys.py configuration and access.") from None
    names = [
        tag["name"]
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("name"), str)
        and tag["name"]
        and "misp-galaxy" not in tag["name"]
    ]
    return list(dict.fromkeys(names)), comments


def handler(q=False):
    if q is False:
        return False
    try:
        try:
            request = json.loads(q)
        except (ValueError, TypeError):
            raise ModuleError("Invalid JSON request.") from None
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        config = request.get("config")
        if not isinstance(config, dict):
            raise ModuleError("Missing MWDB configuration.")
        api_key = config.get("mwdb_apikey")
        if not isinstance(api_key, str) or not api_key.strip():
            raise ModuleError("Missing MWDB API key.")
        api_url, file_url = _urls(config.get("mwdb_url"))
        public = _boolean(config, "mwdb_public", mwdb_public_default)
        include_event = _boolean(config, "include_tags_event")
        include_attribute = _boolean(config, "include_tags_attribute")
        attribute_key = config.get("mwdb_misp_attribute")
        if attribute_key is not None and not isinstance(attribute_key, str):
            raise ModuleError("mwdb_misp_attribute must be an attribute key name.")
        attributes = None
        if attribute_key and attribute_key.strip():
            event_id = request.get("event_id")
            if not isinstance(event_id, (str, int)) or isinstance(event_id, bool) or not str(event_id).strip():
                raise ModuleError("event_id is required when mwdb_misp_attribute is configured.")
            attributes = {attribute_key.strip(): str(event_id)}
        filename, data = _sample(request)
        tags, comments = _metadata(request, include_event, include_attribute)
    except ModuleError as error:
        return {"error": str(error)}

    try:
        mwdb = MWDB(api_key=api_key.strip(), api_url=api_url, config_path=None, obey_ratelimiter=False)
        file_object = mwdb.upload_file(filename, data, attributes=attributes, tags=tags, public=public)
    except (MWDBError, RequestException):
        return {"error": "Unable to upload sample to MWDB; check the API key, permissions and server availability."}

    link = file_url + file_object.id
    comment = "Link to MWDB sample"
    try:
        for text in comments:
            file_object.add_comment(text)
    except (MWDBError, RequestException):
        # Upload succeeded: return the link so callers do not retry the submission.
        comment += "; sample uploaded, but MWDB comments could not be added"
    return {"results": [{"types": "link", "values": link, "comment": comment}]}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
