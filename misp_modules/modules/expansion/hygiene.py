import json
import re
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "hostname", "url", "ip-src", "ip-dst", "md5", "sha1", "sha256", "email-src", "email-dst"],
    "format": "misp_standard",
}
moduleconfig = ["warninglists_path", "slow_search", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Hygiene Warninglist Check",
    "description": "Check an observable against local MISP warninglists and record the matching lists.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["pymispwarninglists>=1.7.0"],
    "features": (
        "Uses the warninglists bundled with pymispwarninglists without downloading during enrichment. Optional"
        " warninglists_path points to a local repository containing lists/*/list.json. slow_search defaults to true for"
        " CIDR and hostname-aware matching; false selects exact matching. Matching-list name, version, type and"
        " description become warninglist-match objects. max_results defaults to 25 (1-100). Matches are context for"
        " analyst review, not proof of benignness; source detection flags and scores are preserved."
    ),
    "references": ["https://github.com/MISP/misp-warninglists", "https://github.com/MISP/PyMISPWarningLists"],
    "input": "domain, hostname, url, ip-src, ip-dst, md5, sha1, sha256, email-src, email-dst MISP attribute.",
    "output": "Referenced enrichment objects and pivotable attributes.",
}
TIMEOUT = 30
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ModuleError(ValueError):
    """An actionable error that contains no request credentials."""


def _domain(value):
    if not isinstance(value, str):
        raise ModuleError("Invalid domain or hostname.")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        (re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split("."))
    ):
        raise ModuleError("Invalid domain or hostname.")
    return value


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-fA-F]{%d}" % HASH_LENGTHS[kind], value):
        raise ModuleError(f"Invalid {kind} hash.")
    return value.lower()


def _value(attribute):
    kind, value = (attribute["type"], attribute["value"].strip())
    if kind in HASH_LENGTHS:
        return _hash(kind, value)
    if kind in ("ip-src", "ip-dst"):
        return str(ip_address(value))
    if kind in ("domain", "hostname"):
        return _domain(value)
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ModuleError("Invalid HTTP(S) URL.")
    return value


def _limit(config, key="max_results", default=25, maximum=100):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or (not 1 <= int(value) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(value)


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


def _cap(event, attribute, rows, limit, more=False):
    if len(rows) > limit or more:
        _annotation(
            event, attribute, moduleinfo["name"] + " result limit", {"limit": limit, "more_results_available": True}
        )
    return rows[:limit]


def _results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all((attribute.get(k) for k in ("type", "value", "uuid"))):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty string.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        for key in []:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError, AttributeError, IndexError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _expand(event, attribute, config):
    try:
        from pymispwarninglists import WarningLists
    except ImportError:
        raise ModuleError("The pymispwarninglists package is required for Hygiene.") from None
    value = _value(attribute)
    if attribute["type"] in ("email-src", "email-dst"):
        local, separator, domain = value.rpartition("@")
        if not separator or not local:
            raise ModuleError("A valid email address is required.")
        value = local + "@" + _domain(domain)
    limit = _limit(config)
    slow = config.get("slow_search", "true")
    if str(slow).lower() not in ("true", "false"):
        raise ModuleError("slow_search must be true or false.")
    path = config.get("warninglists_path")
    if path:
        path = Path(path)
        if not path.is_dir() or not (path / "lists").is_dir():
            raise ModuleError("warninglists_path must contain a lists directory.")
    try:
        warninglists = WarningLists(slow_search=str(slow).lower() == "true", path_to_repo=path)
        rows = [
            row
            for row in warninglists.search(value)
            if not getattr(row, "matching_attributes", None)
            or "ALL" in row.matching_attributes
            or attribute["type"] in row.matching_attributes
        ]
    except Exception:
        raise ModuleError("The local warninglists could not be loaded or searched.") from None
    for row in _cap(event, attribute, rows, limit):
        obj = MISPObject(
            "warninglist-match",
            strict=True,
            misp_objects_path_custom=Path(__file__).resolve().parents[2] / "data" / "hygiene",
        )
        for relation, raw in (
            ("value", value),
            ("warninglist-name", row.name),
            ("warninglist-version", row.version),
            ("warninglist-type", row.type),
            ("description", row.description),
            ("matching-mode", "smart" if str(slow).lower() == "true" else "exact"),
        ):
            obj.add_attribute(relation, value=str(raw), to_ids=False, disable_correlation=True)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
    return _results(event)
