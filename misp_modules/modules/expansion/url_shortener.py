"""Resolve known URL shorteners into a standard shortened-link object."""

import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from uuid import UUID

import certifi
import urllib3
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["url"], "format": "misp_standard"}
moduleconfig = ["additional_shorteners", "max_redirects", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "URL Shortener Resolver",
    "description": "Resolve known HTTP(S) URL shorteners into a shortened-link object.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["urllib3", "certifi", "PyMISP", "Direct outbound HTTP(S) and DNS access"],
    "features": (
        "Resolve known shorteners and optional additional_shorteners (comma-separated exact hostnames). Follow"
        " at most max_redirects HTTP redirects (default 10, maximum 20), using HEAD with streamed GET fallback"
        " on HTTP 405/501. timeout is per request (default 10 seconds, maximum 30); DNS uses the system resolver."
        " Every hop must resolve exclusively to public addresses on ports 80/443. Connections are pinned to a"
        " validated address with TLS hostname verification. Return the original attribute and a shortened-link"
        " object with the final destination and ordered redirect history. No API key, proxy, browser, JavaScript"
        " or HTML redirect processing is used. Generated attributes have to_ids=false."
    ),
    "references": [
        "https://github.com/MISP/misp-modules/issues/260",
        "https://github.com/MISP/misp-objects/blob/main/objects/shortened-link/definition.json",
    ],
    "input": "A URL attribute containing type, value and UUID.",
    "output": "A shortened-link object referencing the original URL attribute.",
}

# Exact matches only: neither arbitrary subdomains nor lookalike suffixes are trusted.
SHORTENERS = frozenset(
    {
        "amzn.to",
        "bit.do",
        "bit.ly",
        "buff.ly",
        "cutt.ly",
        "db.tt",
        "fb.me",
        "goo.gl",
        "ift.tt",
        "is.gd",
        "j.mp",
        "lnkd.in",
        "ow.ly",
        "rb.gy",
        "rebrand.ly",
        "s.id",
        "shorturl.at",
        "t.co",
        "t.ly",
        "tiny.cc",
        "tiny.one",
        "tinyurl.com",
        "trib.al",
        "v.gd",
        "youtu.be",
    }
)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _hostname(value):
    host = value.encode("idna").decode("ascii").lower().rstrip(".")
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
    ):
        raise ValueError("Invalid hostname.")
    return host


def _check_url_text(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or "\\" in value
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("An HTTP(S) URL without whitespace, control characters or backslashes is required.")


def _url(value):
    _check_url_text(value)
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc:
        raise ValueError("An HTTP(S) URL with a hostname and without credentials is required.")
    if "%" in parts.hostname or parts.netloc.endswith(":"):
        raise ValueError("Invalid URL hostname or port.")
    port = parts.port
    if port is not None and port not in (80, 443):
        raise ValueError("Only HTTP(S) ports 80 and 443 are supported.")
    try:
        host = str(ipaddress.ip_address(parts.hostname))
    except ValueError:
        host = _hostname(parts.hostname)
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        authority += f":{port}"
    return urlunsplit(
        (
            parts.scheme,
            authority,
            quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"),
            quote(parts.query, safe="%:@!$&'()*+,;=/?-._~"),
            quote(parts.fragment, safe="%:@!$&'()*+,;=/?-._~"),
        )
    )


def _limit(config, key, default, maximum):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,2}", str(value)) or not 1 <= int(value) <= maximum:
        raise ValueError(f"{key} must be an integer between 1 and {maximum}.")
    return int(value)


def _shorteners(config):
    extra = config.get("additional_shorteners")
    if extra is None or extra == "":
        return SHORTENERS
    if not isinstance(extra, str):
        raise ValueError("additional_shorteners must be a comma-separated list of hostnames.")
    return SHORTENERS | {_hostname(host.strip()) for host in extra.split(",")}


def _request(url, method, timeout):
    """Validate DNS and connect to the selected IP without resolving the hostname again."""
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = [
            ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ]
    except (OSError, ValueError):
        raise ValueError("A URL hostname could not be resolved.") from None
    if not addresses or any(
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or getattr(address, "ipv4_mapped", None) is not None
        for address in addresses
    ):
        raise ValueError("Every URL hop must resolve exclusively to public unicast addresses.")
    address = str(addresses[0])
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
        path = urlunsplit(("", "", parts.path, parts.query, ""))
        response = pool.urlopen(
            method,
            path,
            headers={"Host": parts.netloc, "User-Agent": "MISP-modules/URLShortener", "Accept-Encoding": "identity"},
            timeout=urllib3.Timeout(total=timeout),
            retries=False,
            redirect=False,
            preload_content=False,
        )
        # Do not download content, including for GET fallback or terminal destinations.
        return response.status, response.headers.get("Location")
    except (urllib3.exceptions.HTTPError, OSError):
        raise ValueError("A URL request failed or timed out.") from None
    finally:
        if response is not None:
            response.close()
        pool.close()


def _resolve(url, max_redirects, timeout):
    visited = set()
    history = []
    for _ in range(max_redirects + 1):
        # Fragments are not sent to servers and must not disguise a redirect loop.
        key = urlsplit(url)._replace(fragment="").geturl()
        if key in visited:
            raise ValueError("A redirect loop was detected.")
        visited.add(key)
        method = "HEAD"
        status, location = _request(url, method, timeout)
        if status in (405, 501):
            method = "GET"
            status, location = _request(url, method, timeout)
        if status not in REDIRECT_STATUSES:
            if not 200 <= status < 300:
                raise ValueError(f"A URL returned HTTP {status}.")
            if not history:
                raise ValueError("The short URL did not return an HTTP redirect.")
            return url, history
        if not location:
            raise ValueError("An HTTP redirect has no Location header.")
        if len(history) >= max_redirects:
            raise ValueError("The URL exceeds max_redirects.")
        # urljoin silently removes CR/LF and tabs, so reject them before parsing.
        _check_url_text(location)
        # RFC 9110: a redirect without a fragment inherits the current fragment.
        target = urljoin(url, location)
        if "#" not in location and urlsplit(url).fragment:
            target = urlsplit(target)._replace(fragment=urlsplit(url).fragment).geturl()
        target = _url(target)
        history.append({"url": url, "redirect-url": target, "status": status, "method": method})
        url = target
    raise ValueError("The URL exceeds max_redirects.")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not check_input_attribute(attribute):
            raise ValueError(f"{standard_error_message}, containing type, value and uuid.")
        if attribute["type"] != "url":
            raise ValueError("Unsupported attribute type: expected url.")
        if not isinstance(attribute["uuid"], str):
            raise ValueError("The source attribute UUID must be a string.")
        UUID(attribute["uuid"])
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("The config must be a JSON object.")
        url = _url(attribute["value"])
        if urlsplit(url).hostname not in _shorteners(config):
            raise ValueError("Unknown URL shortener. Add its exact hostname to additional_shorteners if needed.")
        maximum = _limit(config, "max_redirects", 10, 20)
        timeout = _limit(config, "timeout", 10, 30)
        source = MISPAttribute()
        source.from_dict(**attribute)
        destination, history = _resolve(url, maximum, timeout)
        obj = MISPObject("shortened-link", strict=True)
        obj.add_attribute("shortened-url", attribute["value"], to_ids=False)
        obj.add_attribute("redirect-url", destination, to_ids=False)
        obj.add_attribute("domain", urlsplit(url).hostname, to_ids=False)
        obj.add_attribute("text", json.dumps({"redirects": history}, ensure_ascii=False), to_ids=False)
        obj.add_reference(source.uuid, "derived-from")
        event = MISPEvent()
        event.add_attribute(**source)
        event.add_object(obj)
        data = json.loads(event.to_json())
        return {"results": {key: data[key] for key in ("Attribute", "Object")}}
    except (ValueError, TypeError, UnicodeError, PyMISPError) as error:
        return {"error": f"URL shortener expansion failed: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
