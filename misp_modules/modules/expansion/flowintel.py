import json
from urllib.parse import urlsplit

import requests

mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "url",
        "uri",
        "link",
        "email",
        "email-src",
        "email-dst",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "filename",
        "filename|md5",
        "filename|sha1",
        "filename|sha256",
        "mutex",
        "regkey",
        "regkey|value",
        "AS",
        "vulnerability",
        "text",
    ],
    "output": ["link"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "description": "Find Flowintel cases containing the queried attribute value.",
    "module-type": ["expansion", "hover"],
    "name": "Flowintel case lookup",
    "requirements": ["requests", "A Flowintel API key and the case attribute lookup API"],
    "features": (
        "Queries standalone and object attributes by exact value, including completed cases. "
        "Returns one link per case visible to the configured Flowintel API user. "
        "Configure url as the Flowintel application root, apikey, and optionally "
        "verify_ssl (default true) and timeout in seconds (default 30)."
    ),
    "references": [
        "https://github.com/flowintel/flowintel",
        "https://github.com/MISP/misp-modules/blob/main/documentation/expansion/flowintel.md",
    ],
    "input": "A MISP attribute value to look up in Flowintel.",
    "output": "Links to matching Flowintel cases, with case titles in the comments.",
}
moduleconfig = ["url", "apikey", "verify_ssl", "timeout"]


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "A JSON object is required."}

    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or attribute.get("type") not in mispattributes["input"]:
        return {"error": "A supported MISP attribute is required."}
    value = attribute.get("value")
    if not isinstance(value, str) or not value.strip():
        return {"error": "A non-empty attribute value is required."}

    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "Invalid Flowintel configuration."}
    url = config.get("url")
    apikey = config.get("apikey")
    if not isinstance(url, str) or not url.strip() or not isinstance(apikey, str) or not apikey.strip():
        return {"error": "Configure the Flowintel url and apikey."}
    url = url.strip().rstrip("/")
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        verify_ssl = config.get("verify_ssl")
        if verify_ssl is None or verify_ssl == "":
            verify_ssl = "true"
        verify_ssl = str(verify_ssl).strip().lower()
        if verify_ssl not in ("true", "false", "1", "0"):
            raise ValueError
        timeout = config.get("timeout")
        if timeout is None or timeout == "":
            timeout = 30
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return {"error": "Invalid Flowintel url, verify_ssl, or timeout configuration."}

    try:
        response = requests.post(
            f"{url}/api/case/search/attribute",
            headers={"X-API-KEY": apikey, "Accept": "application/json"},
            json={"value": value},
            verify=verify_ssl in ("true", "1"),
            timeout=timeout,
            allow_redirects=False,
        )
        if response.status_code in (401, 403):
            return {"error": "Flowintel denied access. Check the API key and user permissions."}
        if response.status_code == 404:
            return {"error": "Flowintel attribute lookup API not found. Check the url and Flowintel version."}
        if response.status_code != 200:
            return {"error": f"Flowintel lookup failed (HTTP {response.status_code})."}
        payload = response.json()
    except requests.exceptions.Timeout:
        return {"error": "Flowintel lookup timed out."}
    except ValueError:
        return {"error": "Flowintel returned invalid JSON."}
    except requests.exceptions.RequestException:
        return {"error": "Could not query Flowintel. Check connectivity and TLS configuration."}

    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        return {"error": "Flowintel returned an invalid case lookup response."}
    results = []
    seen = set()
    for case in payload["cases"]:
        if not isinstance(case, dict) or type(case.get("id")) is not int or case["id"] <= 0:
            return {"error": "Flowintel returned an invalid case lookup response."}
        case_id = case["id"]
        if case_id in seen:
            continue
        seen.add(case_id)
        results.append(
            {
                "type": "link",
                "category": "External analysis",
                "value": f"{url}/case/{case_id}",
                "to_ids": False,
                "comment": f"Flowintel case #{case_id}: {case.get('title', '')}",
            }
        )
    return {"results": {"Attribute": results}}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
