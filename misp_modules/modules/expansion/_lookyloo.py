"""Shared Lookyloo transport and object mapping. Never submits or changes captures."""

import base64
import hashlib
import ipaddress
import json
import math
import re
from importlib import resources
from io import BytesIO
from urllib.parse import urlsplit
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

DEFAULT_URL = "https://lookyloo.circl.lu"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
CONFIG = ["url", "apikey", "timeout", "max_items", "include_raw"]
CAPTURE_CONFIG = ["include_cookies", "include_favicons", "include_extended", "include_misp_export", "include_contacts"]
CORE_ENDPOINTS = ("status", "redirects", "ips", "hostnames", "urls", "hashes", "stats", "modules", "comparables")
EXTENDED_ENDPOINTS = ("storage_state", "console_messages", "ai_export", "tree_dump")


class LookylooError(ValueError):
    pass


def boolean(config, name, default=False):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, int)):
        if str(value).strip().lower() in ("true", "1", "yes", "on"):
            return True
        if str(value).strip().lower() in ("false", "0", "no", "off"):
            return False
    raise LookylooError(f"{name} must be a boolean.")


def integer(config, name, default, minimum, maximum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise LookylooError(f"{name} must be an integer between {minimum} and {maximum}.")
    result = int(value)
    if not minimum <= result <= maximum:
        raise LookylooError(f"{name} must be between {minimum} and {maximum}.")
    return result


def parse_request(query, accepted):
    try:
        request = json.loads(query)
    except (ValueError, TypeError) as error:
        raise LookylooError("Expected a JSON object with an attribute.") from error
    if not isinstance(request, dict):
        raise LookylooError("Expected a JSON object with an attribute.")
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not all(key in attribute for key in ("type", "value", "uuid")):
        raise LookylooError("The attribute must contain type, value and uuid.")
    if attribute["type"] not in accepted or not isinstance(attribute["value"], str) or not attribute["value"].strip():
        raise LookylooError("Unsupported attribute type or empty value.")
    try:
        UUID(str(attribute["uuid"]))
    except (ValueError, TypeError) as error:
        raise LookylooError("Invalid attribute UUID.") from error
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise LookylooError("config must be an object.")
    return attribute, config


def valid_url(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme in ("https", "http") and bool(parsed.hostname) and parsed.port != 0
    except ValueError:
        return False


def capture_uuid(value, base_url):
    """Accept a UUID or this instance's /tree/<uuid> URL, never a foreign URL."""
    if valid_url(value):
        base, parsed = urlsplit(base_url), urlsplit(value)
        prefix = base.path.rstrip("/") + "/tree/"
        if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc) or not parsed.path.startswith(prefix):
            raise LookylooError("Use a capture link from the configured Lookyloo instance.")
        if parsed.query or parsed.fragment:
            raise LookylooError("Use a capture UUID or link without query parameters or fragments.")
        value = parsed.path[len(prefix) :].rstrip("/")
    try:
        return str(UUID(value))
    except (ValueError, TypeError) as error:
        raise LookylooError("Expected a capture UUID or a Lookyloo /tree/<uuid> link.") from error


class Client:
    def __init__(self, config):
        self.base_url = config.get("url") or DEFAULT_URL
        if not isinstance(self.base_url, str) or not valid_url(self.base_url):
            raise LookylooError("url must be an HTTP(S) Lookyloo base URL.")
        parsed = urlsplit(self.base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise LookylooError("url must not contain credentials, query parameters or fragments.")
        self.base_url = self.base_url.rstrip("/")
        try:
            timeout = config.get("timeout")
            self.timeout = 30 if timeout is None or timeout == "" else float(timeout)
        except (TypeError, ValueError) as error:
            raise LookylooError("timeout must be between 1 and 120 seconds.") from error
        if not math.isfinite(self.timeout) or not 1 <= self.timeout <= 120:
            raise LookylooError("timeout must be between 1 and 120 seconds.")
        self.max_items = integer(config, "max_items", 100, 1, 1000)
        self.include_raw = boolean(config, "include_raw", True)
        self.options = {name: boolean(config, name) for name in CAPTURE_CONFIG}
        key = config.get("apikey") or ""
        if not isinstance(key, str) or "\n" in key or "\r" in key:
            raise LookylooError("apikey must be a single line string.")
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-modules/Lookyloo"})
        if key:
            self.session.headers["Authorization"] = key

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def request(self, path, payload=None, params=None, allow_capture_error=False):
        method = "POST" if payload is not None else "GET"
        try:
            with self.session.request(
                method,
                self.base_url + path,
                json=payload,
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    raise LookylooError(f"{path}: HTTP {response.status_code}.")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise LookylooError(f"{path}: response exceeds 5 MiB.")
                data = json.loads(content)
        except requests.RequestException as error:
            # Transport exceptions can contain credentials and private query URLs.
            raise LookylooError(f"{path}: Lookyloo request failed or timed out.") from error
        except (ValueError, UnicodeError) as error:
            if isinstance(error, LookylooError):
                raise
            raise LookylooError(f"{path}: invalid JSON response.") from error
        if not isinstance(data, (dict, list)):
            raise LookylooError(f"{path}: expected a JSON object or list.")
        if isinstance(data, dict) and data.get("error") and not allow_capture_error:
            raise LookylooError(f"{path}: Lookyloo returned an error.")
        return data


def sha512(value):
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{128}", value) is not None


class Parser:
    def __init__(self, attribute, client):
        self.client = client
        self.event = MISPEvent()
        source = MISPAttribute()
        source.from_dict(**attribute)
        self.source = self.event.add_attribute(**source)
        self.captures = {}
        self.urls = {}
        self.files = {}

    @staticmethod
    def add(obj, relation, value, **kwargs):
        if value is not None and value != "":
            return obj.add_attribute(relation, value, to_ids=False, **kwargs)

    def raw(self, obj, name, data):
        if self.client.include_raw:
            self.add(obj, "raw-data", name + ".json", data=BytesIO(json.dumps(data, sort_keys=True).encode()))

    def note(self, obj, message):
        self.add(obj, "text", message)

    def capture(self, identifier, record=None):
        identifier = capture_uuid(identifier, self.client.base_url)
        if identifier in self.captures:
            return self.captures[identifier]
        template = json.loads(
            resources.files("misp_modules").joinpath("data/lookyloo-capture/definition.json").read_text()
        )
        obj = MISPObject("lookyloo-capture", strict=True, misp_objects_template_custom=template)
        self.add(obj, "instance", self.client.base_url)
        self.add(obj, "capture-id", identifier)
        self.add(obj, "permalink", f"{self.client.base_url}/tree/{identifier}")
        obj.add_reference(self.source.uuid, "related-to")
        self.event.add_object(obj)
        self.captures[identifier] = obj
        if record:
            self.add(obj, "title", record.get("title"))
            self.add(obj, "capture-date", record.get("start_timestamp"))
        return obj

    def url(self, capture, value):
        if not isinstance(value, str) or not valid_url(value):
            return None
        key = (str(capture.uuid), value)
        if key not in self.urls:
            obj = MISPObject("url", strict=True)
            self.add(obj, "url", value)
            self.event.add_object(obj)
            capture.add_reference(obj.uuid, "contains")
            self.urls[key] = obj
        return self.urls[key]

    def file(self, capture, digest, urls=()):
        if not sha512(digest):
            return None
        key = (str(capture.uuid), digest.lower())
        if key not in self.files:
            obj = MISPObject("file", strict=True)
            self.add(obj, "sha512", digest.lower())
            self.event.add_object(obj)
            capture.add_reference(obj.uuid, "contains")
            self.files[key] = obj
        obj = self.files[key]
        for value in self.bounded(capture, urls, "hash URLs"):
            url = self.url(capture, value)
            if url and not any(ref.referenced_uuid == url.uuid for ref in obj.references):
                obj.add_reference(url.uuid, "downloaded-from")
        return obj

    def bounded(self, capture, items, label):
        if not isinstance(items, (list, dict, tuple)):
            raise LookylooError(f"Unexpected {label} response format.")
        if len(items) > self.client.max_items:
            self.note(capture, f"{label} truncated to {self.client.max_items} entries; see raw-data for the response.")
        return list(items)[: self.client.max_items]

    def occurrences(self, result, label, limit):
        if not isinstance(result, dict) or not isinstance(result.get("response"), list):
            raise LookylooError("Unexpected Lookyloo lookup response format.")
        for record in result["response"][:limit]:
            if not isinstance(record, dict) or not record.get("capture_uuid"):
                raise LookylooError("Lookup result is missing a capture UUID.")
            obj = self.capture(record["capture_uuid"], record)
            self.raw(obj, label, {"meta": result.get("meta", {}), "response": record})
            meta = result.get("meta") or {}
            if isinstance(meta, dict) and meta.get("warning"):
                self.note(obj, str(meta["warning"]))
            nodes = record.get("urlnodes") or {}
            # IP/hash lookups return node UUID lists, URL/hostname lookups return mappings.
            if isinstance(nodes, dict):
                for identifier in self.bounded(obj, nodes, "URL nodes"):
                    node = nodes[identifier]
                    if not isinstance(node, dict):
                        continue
                    value = node.get("url")
                    if not value and self.source.type == "url":
                        value = self.source.value
                    url = self.url(obj, value)
                    self.file(obj, node.get("hash"), [value] if url else [])

    def enrich(self, identifier):
        info = self.client.request(f"/json/{identifier}/info", allow_capture_error=True)
        if not isinstance(info, dict) or not info.get("uuid"):
            raise LookylooError("Capture info is missing its UUID.")
        if str(info["uuid"]) != identifier:
            raise LookylooError("Capture info returned a different UUID.")
        obj = self.capture(identifier)
        self.raw(obj, "info", info)
        for relation, key in (
            ("url", "url"),
            ("title", "title"),
            ("capture-date", "capture_time"),
            ("user-agent", "user_agent"),
            ("referer", "referer"),
            ("error", "error"),
        ):
            value = info.get(key)
            if relation in ("url", "referer") and value and not valid_url(value):
                continue
            if value is not None and not obj.get_attributes_by_relation(relation):
                self.add(obj, relation, value)
        self.url(obj, info.get("url"))
        endpoints = list(CORE_ENDPOINTS)
        if self.client.options["include_cookies"]:
            endpoints.append("cookies")
        if self.client.options["include_favicons"]:
            endpoints.append("favicons")
        if self.client.options["include_extended"]:
            endpoints.extend(EXTENDED_ENDPOINTS)
        if self.client.options["include_misp_export"]:
            endpoints.append("misp_export")
        for endpoint in endpoints:
            try:
                params = {"algorithm": "sha512", "hashes_only": 0} if endpoint == "hashes" else None
                data = self.client.request(
                    f"/json/{identifier}/{endpoint}", params=params, allow_capture_error=endpoint == "status"
                )
                self.raw(obj, endpoint, data)
                self.parse_endpoint(obj, endpoint, data)
            except (LookylooError, TypeError, KeyError, ValueError) as error:
                self.add(obj, "error", str(error), comment=endpoint)
        if self.client.options["include_contacts"]:
            try:
                data = self.client.request("/json/takedown", payload={"capture_uuid": identifier, "filter": True})
                self.raw(obj, "takedown", data)
                for email in self.bounded(obj, data, "contacts"):
                    if isinstance(email, str) and "@" in email:
                        contact = self.event.add_attribute(
                            "email", email, to_ids=False, comment="Lookyloo takedown contact; no request was sent."
                        )
                        obj.add_reference(contact.uuid, "related-to")
            except (LookylooError, TypeError, ValueError) as error:
                self.add(obj, "error", str(error), comment="takedown")
        image = MISPObject("image", strict=True)
        self.add(image, "link", f"{self.client.base_url}/bin/{identifier}/screenshot")
        self.event.add_object(image)
        obj.add_reference(image.uuid, "related-to")
        for endpoint in ("export", "data", "video"):
            self.add(obj, "download", f"{self.client.base_url}/bin/{identifier}/{endpoint}", comment=endpoint)

    def parse_endpoint(self, obj, endpoint, data):
        body = data.get("response", data) if isinstance(data, dict) else data
        if endpoint in ("status", "redirects", "ips", "hostnames", "urls", "hashes", "favicons") and not isinstance(
            body, dict
        ):
            raise LookylooError(f"Unexpected {endpoint} response format.")
        if endpoint == "status":
            if not isinstance(body, dict) or not isinstance(body.get("status_code"), int):
                raise LookylooError("Unexpected capture status response.")
            self.add(obj, "status", body["status_code"])
            self.add(obj, "error", body.get("error"), comment=endpoint)
        elif endpoint == "redirects":
            for index, value in enumerate(self.bounded(obj, body["redirects"], "redirects")):
                self.add(obj, "redirect", value, comment=f"Redirect position {index + 1}")
                self.url(obj, value)
        elif endpoint in ("ips", "hostnames", "urls"):
            for value in self.bounded(obj, body[endpoint], endpoint):
                if endpoint == "urls":
                    self.url(obj, value)
                elif endpoint == "ips":
                    self.add(obj, "ip", str(ipaddress.ip_address(value)))
                else:
                    self.add(obj, "hostname", value)
        elif endpoint == "hashes":
            mapping = body.get("hashes_with_urls", {})
            if not isinstance(mapping, dict):
                raise LookylooError("Unexpected hashes_with_urls response format.")
            for digest in self.bounded(obj, body["hashes"], "hashes"):
                self.file(obj, digest, mapping.get(digest, []))
        elif endpoint == "cookies":
            for item in self.bounded(obj, body, "cookies"):
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                if not item.get("value"):
                    # PyMISP skips empty object attributes; the cookie template requires a value.
                    cookie = self.event.add_attribute(
                        "cookie",
                        f"{item['name']}=",
                        to_ids=False,
                        comment=json.dumps(item, sort_keys=True),
                    )
                    obj.add_reference(cookie.uuid, "contains")
                    continue
                cookie = MISPObject("cookie", strict=True)
                self.add(cookie, "cookie-name", item["name"])
                self.add(cookie, "cookie-value", item["value"])
                self.add(cookie, "cookie", f"{item['name']}={item.get('value', '')}")
                for relation, key in (("path", "path"), ("secure", "secure"), ("http-only", "httpOnly")):
                    self.add(cookie, relation, item.get(key))
                context = {key: item[key] for key in ("domain", "sameSite", "expires") if key in item}
                if context:
                    self.add(cookie, "text", json.dumps(context, sort_keys=True))
                self.event.add_object(cookie)
                obj.add_reference(cookie.uuid, "contains")
        elif endpoint == "favicons":
            for digest in self.bounded(obj, body["favicons"], "favicons"):
                content = base64.b64decode(body["favicons"][digest], validate=True)
                if not sha512(digest) or hashlib.sha512(content).hexdigest() != digest.lower():
                    raise LookylooError("Favicon content does not match its SHA-512.")
                file_obj = self.file(obj, digest)
                if file_obj:
                    self.add(file_obj, "attachment", f"{digest}.ico", data=BytesIO(content))

    def results(self):
        result = json.loads(self.event.to_json())
        return {"results": {key: result[key] for key in ("Attribute", "Object") if key in result}}
