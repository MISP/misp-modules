import json
import re
from urllib.parse import quote, unquote, urlsplit
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "text",
        "other",
        "malware-type",
        "threat-actor",
        "md5",
        "sha256",
        "filename|md5",
        "filename|sha256",
        "link",
        "url",
    ],
    "output": ["MISP objects", "link", "threat-actor"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Malpedia lookup",
    "description": "Search Malpedia families and actors, or expand a sample hash or Malpedia record URL.",
    "module-type": ["expansion", "hover"],
    "logo": "",
    "requirements": ["requests", "PyMISP", "Optional Malpedia API token; required for sample hash lookups."],
    "features": (
        "Query family and actor names or aliases, canonical family IDs, Malpedia record URLs, and MD5/SHA-256 hashes. "
        "Return related malware, intrusion-set and file objects with source links. Optionally fetch family YARA rules "
        "with their TLP tags. Existing MISP object templates suffice. New attributes use to_ids=false. "
        "Configure apikey, timeout (default 30 seconds), max_results (default 5, maximum 20 per collection), and "
        "include_yara (default false). No sample binaries are downloaded."
    ),
    "references": ["https://malpedia.caad.fkie.fraunhofer.de/usage/api"],
    "input": "Family/actor name, alias or ID, Malpedia details/actor URL, MD5 or SHA-256 attribute.",
    "output": "MISP malware, intrusion-set, file and optional yara objects, reference links and actor attributions.",
}
moduleconfig = ["apikey", "timeout", "max_results", "include_yara"]
BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de"
FAMILY_ID = re.compile(r"[a-z0-9]+\.[a-z0-9_.-]+", re.IGNORECASE)
RECORD_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")


class MalpediaError(Exception):
    pass


def _strings(value):
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item.strip()]
    return []


def _config_value(config, name, default):
    """MISP sends null or empty strings for settings that have not been configured."""
    value = config.get(name, default)
    return default if value is None or value == "" else value


def _integer(config, name, default, maximum):
    value = _config_value(config, name, default)
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise MalpediaError(f"{name} must be an integer between 1 and {maximum}.")
    value = int(value)
    if not 1 <= value <= maximum:
        raise MalpediaError(f"{name} must be an integer between 1 and {maximum}.")
    return value


def _boolean(config, name):
    value = _config_value(config, name, False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "1", "false", "0", ""):
        return value.lower() in ("true", "1")
    raise MalpediaError(f"{name} must be true or false.")


class MalpediaClient:
    def __init__(self, config):
        self.timeout = _integer(config, "timeout", 30, 120)
        self.limit = _integer(config, "max_results", 5, 20)
        self.include_yara = _boolean(config, "include_yara")
        token = _config_value(config, "apikey", "")
        if not isinstance(token, str) or "\n" in token or "\r" in token:
            raise MalpediaError("apikey must be a single-line string.")
        self.headers = {"Accept": "application/json", "User-Agent": "misp-modules/malpedia"}
        self.authenticated = bool(token.strip())
        if self.authenticated:
            self.headers["Authorization"] = f"apitoken {token.strip()}"

    def get(self, path):
        try:
            response = requests.get(
                f"{BASE_URL}/api/{path}", headers=self.headers, timeout=self.timeout, allow_redirects=False
            )
        except requests.exceptions.Timeout:
            raise MalpediaError("Malpedia API request timed out.") from None
        except requests.exceptions.RequestException:
            raise MalpediaError("Unable to contact the Malpedia API.") from None
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            raise MalpediaError("Malpedia denied access. Check the apikey and your account's access permissions.")
        if response.status_code == 429:
            raise MalpediaError("Malpedia API rate limit reached. Try again later.")
        if response.status_code != 200:
            raise MalpediaError(f"Malpedia API returned HTTP status {response.status_code}.")
        try:
            data = response.json()
        except ValueError:
            raise MalpediaError("Malpedia API returned invalid JSON.") from None
        if isinstance(data, dict) and ("detail" in data or "error" in data):
            raise MalpediaError("Malpedia API returned an error response.")
        return data


class MalpediaParser:
    def __init__(self, attribute, client):
        self.attribute = attribute
        self.client = client
        self.event = MISPEvent()
        self.event.add_attribute(**attribute)
        self.links = {}
        self.families = {}
        self.attributions = {}

    @staticmethod
    def _add(obj, relation, value):
        if value is not None and value != "":
            obj.add_attribute(relation, value=value, to_ids=False)

    @staticmethod
    def _note(obj, message):
        obj.comment = f"{obj.comment}\n{message}" if obj.get("comment") else message

    def _link(self, obj, url):
        if not isinstance(url, str) or urlsplit(url).scheme not in ("http", "https"):
            return
        if url not in self.links:
            self.links[url] = self.event.add_attribute(
                "link", url, to_ids=False, comment="Malpedia reference; not an indicator of malicious infrastructure."
            )
        obj.add_reference(self.links[url].uuid, "described-by")

    def _metadata(self, obj, data, mapped):
        remaining = {key: value for key, value in data.items() if key not in mapped and value not in (None, [], {}, "")}
        if remaining:
            self._note(obj, "Malpedia metadata: " + json.dumps(remaining, ensure_ascii=False, sort_keys=True))

    def family(self, family_id, data):
        if family_id in self.families:
            return self.families[family_id]
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("common_name"), str)
            or not RECORD_ID.fullmatch(family_id)
        ):
            raise MalpediaError("Malpedia returned an unexpected family record.")
        obj = MISPObject("malware", strict=True)
        obj.comment = f"Malpedia family: {family_id}"
        self._add(obj, "name", data.get("common_name") or family_id)
        self._add(obj, "is_family", True)
        for alias in dict.fromkeys([family_id] + _strings(data.get("alt_names"))):
            self._add(obj, "alias", alias)
        self._add(obj, "description", data.get("description"))
        self._metadata(obj, data, {"common_name", "alt_names", "description", "urls", "attribution"})
        self._link(obj, f"{BASE_URL}/details/{quote(family_id, safe='')}")
        for url in _strings(data.get("urls")):
            self._link(obj, url)
        for name in _strings(data.get("attribution")):
            if name not in self.attributions:
                self.attributions[name] = self.event.add_attribute(
                    "threat-actor", name, to_ids=False, comment="Attribution reported by Malpedia."
                )
            obj.add_reference(self.attributions[name].uuid, "attributed-to")
        obj.add_reference(self.attribute["uuid"], "related-to")
        self.event.add_object(obj)
        self.families[family_id] = obj
        return obj

    def actor(self, actor_id, data):
        if not isinstance(data, dict) or not isinstance(data.get("value"), str) or not RECORD_ID.fullmatch(actor_id):
            raise MalpediaError("Malpedia returned an unexpected actor record.")
        obj = MISPObject("intrusion-set", strict=True)
        obj.comment = f"Malpedia actor: {actor_id}"
        self._add(obj, "name", data.get("value") or actor_id)
        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        for alias in dict.fromkeys([actor_id] + _strings(meta.get("synonyms"))):
            self._add(obj, "aliases", alias)
        self._add(obj, "description", data.get("description"))
        self._metadata(obj, data, {"value", "description", "families", "meta"})
        self._metadata(obj, meta, {"synonyms", "refs"})
        self._link(obj, f"{BASE_URL}/actor/{quote(actor_id, safe='')}")
        for url in _strings(meta.get("refs")):
            self._link(obj, url)
        families = data.get("families", {})
        if not isinstance(families, dict):
            raise MalpediaError("Malpedia returned an unexpected actor families collection.")
        if len(families) > self.client.limit:
            self._note(obj, f"Related families limited to {self.client.limit} of {len(families)} results.")
        for family_id, family_data in list(families.items())[: self.client.limit]:
            family = self.family(family_id, family_data)
            obj.add_reference(family.uuid, "uses")
        obj.add_reference(self.attribute["uuid"], "related-to")
        self.event.add_object(obj)

    def sample(self, digest, hash_type):
        if not self.client.authenticated:
            raise MalpediaError("A Malpedia apikey is required for sample hash lookups.")
        data = self.client.get(f"get/sample/{digest}/info")
        if data is None or data == {}:
            return
        if not isinstance(data, dict) or not any(key in data for key in ("md5", "sha256", "family")):
            raise MalpediaError("Malpedia returned an unexpected sample-info record.")
        obj = MISPObject("file", strict=True)
        obj.comment = f"Malpedia sample info: {digest}"
        self._add(obj, hash_type, digest)
        for kind, length in (("md5", 32), ("sha256", 64)):
            value = data.get(kind)
            if value is not None:
                if not isinstance(value, str) or not re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", value):
                    raise MalpediaError("Malpedia returned an invalid sample hash.")
                if kind == hash_type and value.lower() != digest:
                    raise MalpediaError("Malpedia returned sample info for a different hash.")
                if kind != hash_type:
                    self._add(obj, kind, value.lower())
        self._metadata(obj, data, {"md5", "sha256"})
        self._link(obj, f"{BASE_URL}/api/get/sample/{digest}/info")
        obj.add_reference(self.attribute["uuid"], "related-to")
        self.event.add_object(obj)
        for family_id in _strings(data.get("family"))[: self.client.limit]:
            if not FAMILY_ID.fullmatch(family_id):
                continue
            try:
                family_data = self.client.get(f"get/family/{quote(family_id, safe='')}")
                if family_data:
                    family = self.family(family_id, family_data)
                    obj.add_reference(family.uuid, "belongs-to")
            except MalpediaError as error:
                self._note(obj, f"Family expansion unavailable: {error}")

    def search(self, kind, needle):
        data = self.client.get(f"find/{kind}/{quote(needle, safe='')}")
        if data is None:
            return
        if not isinstance(data, list) or any(
            not isinstance(hit, dict) or not isinstance(hit.get("name"), str) for hit in data
        ):
            raise MalpediaError(f"Malpedia returned unexpected {kind} search results.")
        # Prefer an exact identifier, name or synonym over broad substring matches.
        exact = [
            hit
            for hit in data
            if needle.casefold()
            in {
                value.casefold()
                for value in (
                    [hit["name"]]
                    + _strings(hit.get("common_name"))
                    + _strings(hit.get("alt_names"))
                    + _strings(hit.get("synonyms"))
                )
            }
        ]
        hits = list({hit["name"]: hit for hit in exact or data}.values())
        for hit in hits[: self.client.limit]:
            record_id = hit["name"]
            if not RECORD_ID.fullmatch(record_id):
                raise MalpediaError("Malpedia returned an invalid record identifier.")
            record = self.client.get(f"get/{kind}/{quote(record_id, safe='')}")
            if record:
                getattr(self, kind)(record_id, record)
        if len(hits) > self.client.limit:
            self.event.add_attribute(
                "comment",
                f"Malpedia {kind} search limited to {self.client.limit} of {len(hits)} matches.",
                to_ids=False,
            )

    def yara(self):
        if not self.client.include_yara:
            return
        for family_id, family in list(self.families.items())[: self.client.limit]:
            try:
                data = self.client.get(f"get/yara/{quote(family_id, safe='')}")
                if data is None:
                    continue
                if not isinstance(data, dict):
                    raise MalpediaError("Unexpected YARA response format.")
                files = []
                for tlp, rules in data.items():
                    if tlp not in ("tlp_white", "tlp_clear", "tlp_green", "tlp_amber", "tlp_red") or not isinstance(
                        rules, dict
                    ):
                        raise MalpediaError("Unexpected YARA sharing level or rule collection.")
                    files.extend((tlp, filename, rule) for filename, rule in rules.items())
                if len(files) > self.client.limit:
                    self._note(family, f"YARA results limited to {self.client.limit} of {len(files)} rule files.")
                for tlp, filename, rule in files[: self.client.limit]:
                    if not isinstance(rule, str) or not rule.strip():
                        raise MalpediaError("Unexpected YARA rule source.")
                    obj = MISPObject("yara", strict=True)
                    obj.comment = f"Malpedia rule file: {filename}; {tlp}"
                    self._add(obj, "yara", rule)
                    self._add(obj, "reference", f"{BASE_URL}/details/{family_id}")
                    for attribute in obj.attributes:
                        attribute.add_tag(tlp.replace("_", ":", 1))
                    obj.add_reference(family.uuid, "detects")
                    self.event.add_object(obj)
            except MalpediaError as error:
                self._note(family, f"YARA expansion unavailable: {error}")
        for family in list(self.families.values())[self.client.limit :]:
            self._note(family, f"YARA lookup omitted: limited to the first {self.client.limit} families.")

    def results(self):
        if not self.event.objects:
            return {"error": "No matching records found on Malpedia."}
        event = json.loads(self.event.to_json())
        return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def _lookup(parser):
    attribute = parser.attribute
    value = attribute["value"].strip()
    kind = attribute["type"]
    if kind in ("md5", "sha256", "filename|md5", "filename|sha256"):
        hash_type = kind.rsplit("|", 1)[-1]
        digest = value.rsplit("|", 1)[-1] if "|" in kind else value
        if ("|" in kind and "|" not in value) or not re.fullmatch(
            rf"[a-fA-F0-9]{{{32 if hash_type == 'md5' else 64}}}", digest
        ):
            raise MalpediaError(f"Invalid {hash_type} hash value.")
        parser.sample(digest.lower(), hash_type)
    elif kind in ("link", "url"):
        url = urlsplit(value)
        parts = url.path.strip("/").split("/")
        if (
            url.scheme not in ("http", "https")
            or url.netloc.lower() != "malpedia.caad.fkie.fraunhofer.de"
            or len(parts) != 2
            or parts[0] not in ("details", "actor")
            or not RECORD_ID.fullmatch(unquote(parts[1]))
        ):
            raise MalpediaError("Expected a Malpedia /details/<family_id> or /actor/<actor_id> URL.")
        record_kind = "family" if parts[0] == "details" else "actor"
        record_id = unquote(parts[1])
        data = parser.client.get(f"get/{record_kind}/{quote(record_id, safe='')}")
        if data:
            getattr(parser, record_kind)(record_id, data)
    elif kind == "threat-actor":
        parser.search("actor", value)
    elif FAMILY_ID.fullmatch(value):
        data = parser.client.get(f"get/family/{quote(value.lower(), safe='')}")
        if data:
            parser.family(value.lower(), data)
    elif kind == "malware-type":
        parser.search("family", value)
    else:
        parser.search("family", value)
        parser.search("actor", value)
    parser.yara()


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "Expected a JSON object request."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not all(key in attribute for key in ("type", "value", "uuid")):
        return {"error": 'An "attribute" containing type, value and uuid is required.'}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    if not isinstance(attribute["value"], str) or not attribute["value"].strip():
        return {"error": "The attribute value must be a non-empty string."}
    try:
        UUID(str(attribute["uuid"]))
        config = request.get("config", {})
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise MalpediaError("config must be an object.")
        # Validate the input before contacting the service; preserve its original flags and tags.
        MISPAttribute().from_dict(**attribute)
        parser = MalpediaParser(attribute, MalpediaClient(config))
        _lookup(parser)
        return parser.results()
    except MalpediaError as error:
        return {"error": str(error)}
    except (ValueError, TypeError, PyMISPError):
        return {"error": "Invalid input attribute or Malpedia record."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
