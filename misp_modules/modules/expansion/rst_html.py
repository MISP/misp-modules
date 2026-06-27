"""rst_html — fetch rendered HTML body / extracted JS as an attachment (GET /scan/html/body[/js]).

Target format: host:port (e.g. drive.google.com:443). Full URLs pass through unchanged.
"""

from __future__ import annotations

import json
from io import BytesIO

import rstapi

from ._rstcloud.client import (
    error,
    misp_event_with_source,
    rst_kwargs,
    scan_group,
    scan_kwargs,
    scan_target,
    standard_results,
    text_result,
    unwrap,
)

misperrors = {"error": "Error"}

_INPUTS = ["url", "domain", "hostname", "ip-src", "ip-dst",
           "ip-src|port", "ip-dst|port", "hostname|port", "domain|port"]
# misp_standard: return the fetched body as a downloadable attachment.
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.2",
    "author": "RST Cloud",
    "description": "Fetch rendered HTML body or extracted JavaScript for a URL/IP target via RST Scan API.",
    "module-type": ["expansion"],
    "name": "RST Cloud HTML Fetcher",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Fetches the rendered HTML body or extracted JavaScript from the target "
        "via RST Scan. Returns a file MISP object with the page attached and "
        "pivotable content hashes. Configurable mode: body (default) or js."
    ),
    "references": ["https://api.rstcloud.net/", "https://pypi.org/project/rstapi/"],
    "input": "URL, domain, hostname, or IP attribute (optional port via config).",
    "output": "file MISP object (page.html or page.js) with hashes and HTTP metadata.",
}
# 'mode' = body | js (default body). 'port' (optional): override default port 443.
moduleconfig = ["api_key", "base_url", "mode", "port", "timeout"]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config") or {}
    if not rst_kwargs(config)["APIKEY"]:
        return error("An RST Cloud API key is required (set api_key in the module config).")
    target = scan_target(request, _INPUTS, config, default_port=443)
    if not target:
        return error("No target found in the request.")

    is_js = (config.get("mode") or "body").lower() == "js"
    client = rstapi.scan(**scan_kwargs(config))
    method = client.GetHtmlBodyJs if is_js else client.GetHtmlBody
    data, err = unwrap(method(target))
    if err:
        return error(f"RST HTML fetch failed: {err}")

    body = data.get("body") if isinstance(data, dict) else (data if isinstance(data, str) else "")
    if not body:
        return text_result(f"{target}: empty response", "RST HTML Fetcher")

    from pymisp import MISPObject

    meta = data if isinstance(data, dict) else {}
    hashes = meta.get("hashes") or {}
    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    # The fetched body IS a file: group it (attachment + pivotable body hashes +
    # response metadata) in a `file` object rather than a lone size string.
    filename = "page.js" if is_js else "page.html"
    label = "extracted JavaScript" if is_js else "HTML body"
    fobj = MISPObject("file")
    fobj.add_attribute("attachment", value=filename,
                       data=BytesIO(body.encode("utf-8", "replace")), to_ids=False)
    fobj.add_attribute("filename", value=filename)
    fobj.add_attribute("mimetype", value="application/javascript" if is_js else "text/html")
    fobj.add_attribute("size-in-bytes", value=meta.get("content_length") or len(body))
    for htype in ("md5", "sha1", "sha256"):
        if hashes.get(htype):
            fobj.add_attribute(htype, value=hashes[htype])
    info = [f"RST {label} for {target}"]
    if meta.get("http_status"):
        info.append(f"HTTP {meta['http_status']}")
    if meta.get("title"):
        info.append(f"title: {meta['title']}")
    if meta.get("truncated"):
        info.append("(body truncated)")
    fobj.add_attribute("text", value="; ".join(info))
    fobj.comment = "RST HTML Fetcher"
    if anchor:
        fobj.add_reference(anchor, "derived-from")
    event.add_object(fobj)
    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
