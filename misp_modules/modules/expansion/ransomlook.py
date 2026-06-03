import json
from importlib.resources import files

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
_OBJECT_NAME = "ransomware-group-post"


def _misp_attribute_types():
    """Return the current PyMISP attribute type list for broad module introspection."""
    try:
        describe_types = files("pymisp.data").joinpath("describeTypes.json")
        with describe_types.open("r", encoding="utf-8") as handle:
            return json.load(handle)["result"]["types"]
    except Exception:
        return [
            "md5",
            "sha1",
            "sha256",
            "filename",
            "ip-src",
            "ip-dst",
            "hostname",
            "domain",
            "email",
            "email-src",
            "email-dst",
            "url",
            "link",
            "comment",
            "text",
            "other",
            "threat-actor",
            "freetext",
        ]


_INPUT_TYPES = _misp_attribute_types()
if "freetext" not in _INPUT_TYPES:
    _INPUT_TYPES.append("freetext")


mispattributes = {
    "input": _INPUT_TYPES,
    "output": ["MISP objects"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "description": "Query the RansomLook API and return matching ransomware leak-site posts as MISP objects.",
    "module-type": ["expansion", "hover"],
    "name": "RansomLook Lookup",
    "logo": "",
    "requirements": ["No API key required."],
    "features": (
        "The module accepts any MISP attribute value, including text and free-text attributes, and searches across"
        " RansomLook posts using the /api/search endpoint. Matching posts are converted to the MISP"
        f" {_OBJECT_NAME} object format."
    ),
    "references": [
        "https://www.ransomlook.io/",
        "https://www.ransomlook.io/doc/",
        "https://github.com/MISP/misp-objects/blob/main/objects/ransomware-group-post/definition.json",
    ],
    "input": "Any MISP attribute value to search in RansomLook posts.",
    "output": f"RansomLook hits represented as {_OBJECT_NAME} MISP objects.",
}
moduleconfig = []
api_url = "https://www.ransomlook.io/api"

_OBJECT_MAPPING = {
    "title": ("post_title", "title", "name", "victim", "victim_name"),
    "entity-name": ("victim", "victim_name", "entity_name", "post_title", "title"),
    "ransomware-group": ("group_name", "group", "group_slug", "ransomware_group"),
    "description": ("description", "post_body", "body", "content", "summary"),
    "date": ("date", "updated", "last_seen", "last_update"),
    "date-published": ("published", "date_published", "discovered", "first_seen", "created"),
    "geo": ("country", "country_name", "country_code", "location", "geo"),
    "sector": ("sector", "industry", "activity"),
    "severity": ("severity",),
    "website": ("website", "domain", "fqdn"),
    "link": ("url", "link", "post_url", "source_url"),
    "leak-site-url": ("leak_site_url", "leak_url", "post_url", "url", "link"),
}


class RansomLookParser:
    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    @staticmethod
    def _normalise(value):
        if value is None:
            return None
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            value = value.strip()
            return value or None
        if isinstance(value, list):
            values = [RansomLookParser._normalise(entry) for entry in value]
            values = [entry for entry in values if entry]
            return ", ".join(values) if values else None
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True)
        return str(value).strip() or None

    @staticmethod
    def _get_value(hit, keys):
        for key in keys:
            value = RansomLookParser._normalise(hit.get(key))
            if value:
                return value
        return None

    @staticmethod
    def _extract_hits(response):
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            for key in ("results", "data", "hits", "posts"):
                value = response.get(key)
                if isinstance(value, list):
                    return value
        return []

    @staticmethod
    def _object_has_required_attribute(misp_object):
        required_relations = {"title", "description", "link", "website", "leak-site-url"}
        return any(attribute.object_relation in required_relations for attribute in misp_object.attributes)

    def parse_search_result(self, response):
        for hit in self._extract_hits(response):
            if not isinstance(hit, dict):
                continue
            ransomlook_object = MISPObject(_OBJECT_NAME)
            for object_relation, keys in _OBJECT_MAPPING.items():
                value = self._get_value(hit, keys)
                if value:
                    ransomlook_object.add_attribute(object_relation, value=value)
            if not self._object_has_required_attribute(ransomlook_object):
                continue
            if self.attribute.get("uuid"):
                ransomlook_object.add_reference(self.attribute["uuid"], "related-to")
            self.misp_event.add_object(**ransomlook_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Object",) if event.get(key)}
        if not results:
            return {"error": f"No results found on RansomLook for this {self.attribute['type']} attribute."}
        return {"results": results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an UUID."}

    attribute = request["attribute"]
    query = attribute["value"]
    headers = {"User-Agent": "misp-modules"}
    try:
        response = requests.get(f"{api_url}/search", params={"q": query}, headers=headers, timeout=30)
        response.raise_for_status()
        search_result = response.json()
    except requests.exceptions.HTTPError as http_error:
        return {"error": f"RansomLook API returned HTTP status {http_error.response.status_code}."}
    except requests.exceptions.RequestException as request_error:
        return {"error": f"RansomLook API request failed: {request_error}."}
    except ValueError:
        return {"error": "RansomLook API returned an invalid JSON response."}

    parser = RansomLookParser(attribute)
    parser.parse_search_result(search_result)
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
