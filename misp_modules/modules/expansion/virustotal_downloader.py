import hashlib
import json
import re
from io import BytesIO
from urllib.parse import urljoin, urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256"], "format": "misp_standard"}
moduleconfig = ["apikey", "max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "VirusTotal Sample Downloader",
    "description": "Download an existing file from VirusTotal by hash.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Requires a VirusTotal API key with file download entitlement. Uses GET /api/v3/files/{hash}/download. Streams"
        " at most max_size_mb (default 50, range 1-100) and verifies the downloaded file against the requested hash."
        " Signed HTTPS redirects are followed without forwarding the API key. Returns raw bytes as a MISP attachment in"
        " a file object with MD5, SHA-1 and SHA-256 hashes; no sample is executed or submitted."
    ),
    "references": ["https://docs.virustotal.com/reference/files-download"],
    "input": "md5, sha1, sha256 MISP attribute.",
    "output": "A file object with a binary attachment and verified hashes.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch(
        "[0-9a-fA-F]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value
    ):
        raise ModuleError(f"Invalid {kind} hash.")
    return value.lower()


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


def _download(value, apikey, maximum):
    url = f"https://www.virustotal.com/api/v3/files/{value}/download"
    headers = {"x-apikey": apikey}
    for attempt in range(4):
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT, stream=True, allow_redirects=False)
        except requests.RequestException:
            raise ModuleError("VirusTotal download failed or timed out.") from None
        try:
            if response.status_code in (301, 302, 303, 307, 308):
                target = urljoin(url, response.headers.get("Location", ""))
                parsed = urlsplit(target)
                if (
                    not response.headers.get("Location")
                    or parsed.scheme != "https"
                    or (not parsed.hostname)
                    or parsed.username
                    or parsed.password
                ):
                    raise ModuleError("VirusTotal returned an invalid download redirect.")
                url, headers = (target, {})
                continue
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise ModuleError(f"VirusTotal returned HTTP {response.status_code}.")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > maximum):
                raise ModuleError("The download exceeds max_size_mb or has an invalid Content-Length.")
            content = BytesIO()
            for chunk in response.iter_content(chunk_size=65536):
                if content.tell() + len(chunk) > maximum:
                    raise ModuleError("The download exceeds max_size_mb.")
                content.write(chunk)
            return content.getvalue()
        except requests.RequestException:
            raise ModuleError("VirusTotal download failed or timed out.") from None
        finally:
            response.close()
    raise ModuleError("VirusTotal returned too many download redirects.")


def _expand(event, attribute, config):
    kind = attribute["type"]
    value = _hash(kind, attribute["value"].strip())
    maximum = _limit(config, "max_size_mb", 50, 100) * 1024 * 1024
    content = _download(value, config["apikey"], maximum)
    if content is None:
        return _results(event)
    if hashlib.new(kind, content).hexdigest() != value:
        raise ModuleError("The downloaded file does not match the requested hash.")
    obj = MISPObject("file")
    obj.comment = "Downloaded from VirusTotal"
    obj.add_attribute("attachment", value=value + ".bin", data=BytesIO(content), to_ids=False)
    obj.add_attribute("size-in-bytes", value=len(content), to_ids=False)
    for algorithm in ("md5", "sha1", "sha256"):
        obj.add_attribute(algorithm, value=hashlib.new(algorithm, content).hexdigest(), to_ids=False)
    obj.add_reference(attribute["uuid"], "related-to")
    event.add_object(obj)
    return _results(event)
