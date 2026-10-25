import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from io import BytesIO
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit

import certifi
import urllib3
from bs4 import BeautifulSoup
from markdownify import markdownify
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["url"], "format": "misp_standard"}
moduleconfig = ["max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Import External Reference",
    "description": "Capture a public web reference as Markdown or a PDF attachment.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["urllib3", "certifi", "beautifulsoup4", "markdownify"],
    "features": (
        "Downloads a public HTTP(S) URL on ports 80 or 443, with a 30-second wall-clock deadline and at most five"
        " redirects. Resolves and validates every hop, connects directly to the validated public address and verifies"
        " TLS against the original hostname. Private, reserved and mixed public/private DNS answers are rejected. No"
        " proxy or browser is used. max_size_mb defaults to 5 (1-25), enforced while streaming content. HTML is"
        " converted into Markdown; PDFs are preserved. Returns a page-capture object referencing the URL attribute."
    ),
    "references": ["https://www.misp-project.org/objects.html#_page_capture"],
    "input": "url MISP attribute.",
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


def _public_target(value):
    if "\\" in value or any((ord(c) < 32 for c in value)):
        raise ModuleError("Invalid reference URL.")
    parts = urlsplit(value)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise ModuleError("A public HTTP(S) URL without credentials or a fragment is required.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in (80, 443):
        raise ModuleError("Only HTTP(S) ports 80 and 443 are allowed.")
    host = parts.hostname.encode("idna").decode("ascii")
    try:
        addresses = [ip_address(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except (socket.gaierror, ValueError):
        raise ModuleError("The reference hostname could not be resolved.") from None
    if not addresses or any(
        (
            not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, "ipv4_mapped", None) is not None
            for ip in addresses
        )
    ):
        raise ModuleError("The reference must resolve only to public addresses.")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parts.query:
        path += "?" + quote(parts.query, safe="%:@!$&'()*+,;=/?-._~")
    return (parts, host, str(addresses[0]), port, path)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ModuleError("The reference exceeded its 30-second deadline.")
    return remaining


def _fetch(value, maximum):
    deadline = time.monotonic() + 30
    for _ in range(6):
        parts, host, address, port, path = _public_target(value)
        if parts.scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                address,
                port,
                assert_hostname=host,
                server_hostname=host,
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=certifi.where(),
            )
        else:
            pool = urllib3.HTTPConnectionPool(address, port)
        response = None
        try:
            response = pool.urlopen(
                "GET",
                path,
                headers={
                    "Host": ("[" + host + "]" if ":" in host else host) + ":" + str(port),
                    "User-Agent": "MISP-modules/ReferenceCapture",
                    "Accept-Encoding": "identity",
                },
                timeout=urllib3.Timeout(total=_remaining(deadline)),
                retries=False,
                redirect=False,
                preload_content=False,
            )
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise ModuleError("The reference redirect has no location.")
                value = urljoin(value, location)
                continue
            if response.status != 200:
                raise ModuleError(f"The reference returned HTTP {response.status}.")
            if response.headers.get("Content-Encoding", "identity").strip().lower() not in ("", "identity"):
                raise ModuleError(
                    "Encoded references are not supported; the server must honor Accept-Encoding: identity."
                )
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in ("text/html", "application/xhtml+xml", "application/pdf"):
                raise ModuleError("Only HTML and PDF references are supported.")
            raw = bytearray()
            connection = response.connection
            sock = connection.sock if connection is not None else None
            if sock is None:
                # HTTPConnection may detach a socket when the response says Connection: close.
                sock = response._fp.fp.raw._sock
            while True:
                sock.settimeout(_remaining(deadline))
                chunk = response.read1(min(65536, maximum + 1 - len(raw)), decode_content=False)
                _remaining(deadline)
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > maximum:
                    raise ModuleError("The reference exceeds max_size_mb.")
                if response.closed:
                    break
            return (value, content_type, bytes(raw))
        except (urllib3.exceptions.HTTPError, OSError):
            raise ModuleError("The reference request failed or timed out.") from None
        finally:
            if response is not None:
                response.close()
            pool.close()
    raise ModuleError("The reference exceeds the redirect limit.")


def _expand(event, attribute, config):
    maximum = _limit(config, "max_size_mb", 5, 25) * 1024 * 1024
    value, content_type, raw = _fetch(_value(attribute), maximum)
    if not raw:
        raise ModuleError("The reference is empty.")
    if content_type == "application/pdf":
        if not raw.startswith(b"%PDF-"):
            raise ModuleError("The reference is not a PDF document.")
        filename = "reference.pdf"
    else:
        soup = BeautifulSoup(raw, "html.parser")
        for tag in soup.find_all(["script", "style", "iframe", "object", "embed"]):
            tag.decompose()
        raw = markdownify(str(soup), heading_style="ATX").encode("utf-8")
        if len(raw) > maximum:
            raise ModuleError("The converted reference exceeds max_size_mb.")
        filename = "reference.md"
    obj = MISPObject("page-capture", strict=True, misp_objects_path_custom=Path(__file__).resolve().parents[2] / "data")
    obj.add_attribute("url", value=value, to_ids=False)
    obj.add_attribute("attachment", value=filename, data=BytesIO(raw), to_ids=False)
    obj.add_attribute("capture-date", value=datetime.now(timezone.utc).isoformat(), to_ids=False)
    obj.add_reference(attribute["uuid"], "derived-from")
    event.add_object(obj)
    return _results(event)
