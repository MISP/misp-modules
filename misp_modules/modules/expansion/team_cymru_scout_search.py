import json

import requests
from pymisp import MISPEvent

misperrors = {"error": "Error"}
mispattributes = {"input": ["text"], "format": "misp_standard"}
moduleconfig = ["apikey", "days"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Team Cymru Scout Search",
    "description": "Run an explicit Scout search query and import the returned intelligence.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "misp-stix (included in the all extra)"],
    "features": (
        "The text attribute is used verbatim as Scout search syntax; no MISP or STIX pattern is inferred. Uses GET"
        " /search with query and days parameters. days defaults to 7 (1-90). STIX 2 results are converted by misp-stix,"
        " preserving relationships, source context and markings. Install the all dependency extra for misp-stix"
        " support."
    ),
    "references": ["https://scout.cymru.com/"],
    "input": "text MISP attribute.",
    "output": "MISP attributes, objects and tags converted from Scout search results.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _get(url, **kwargs):
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code == 204:
        return None
    if response.status_code != 200:
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _limit(config, key="max_results", default=25, maximum=100):
    raw = config.get(key)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool) or not str(raw).isdigit() or (not 1 <= int(raw) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(raw)


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
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        for key in ["apikey"]:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _convert(event, attribute, data):
    if data is None or data == {}:
        return _results(event)
    if not isinstance(data, dict) or data.get("type") != "bundle" or (not isinstance(data.get("objects"), list)):
        raise ModuleError("Scout returned an unexpected STIX bundle.")
    if not data["objects"]:
        return _results(event)
    try:
        from misp_stix_converter import ExternalSTIX2toMISPParser
        from stix2 import parse

        parser = ExternalSTIX2toMISPParser()
        parser.load_stix_bundle(parse(json.dumps(data), allow_custom=True))
        parser.parse_stix_bundle(single_event=True)
        converted = parser.misp_event
    except ImportError:
        raise ModuleError("The misp-stix package is required for Scout enrichment.") from None
    except Exception:
        raise ModuleError("The Scout STIX bundle could not be converted.") from None
    if parser.errors:
        if not converted.attributes and not converted.objects:
            raise ModuleError("The Scout STIX bundle contains no usable converted intelligence.")
        event.add_attribute(
            "text",
            "Some Scout intelligence could not be converted; results are partial.",
            to_ids=False,
            disable_correlation=True,
            comment="Scout conversion notice",
        )
    for item in converted.attributes:
        item.to_ids = False
        event.add_attribute(**item)
    for obj in converted.objects:
        for item in obj.attributes:
            item.to_ids = False
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)
    for tag in converted.tags:
        event.add_tag(tag)
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object", "Tag")}}


def _expand(event, attribute, config):
    days = _limit(config, "days", 7, 90)
    query = attribute["value"].strip()
    data = _get(
        "https://taxii.cymru.com/api/scout/search",
        params={"query": query, "days": days},
        headers={"Authorization": "Bearer " + config["apikey"], "Accept": "application/json"},
    )
    return _convert(event, attribute, data)
