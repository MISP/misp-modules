"""rst_screenshot — capture a page screenshot as an image object (GET /scan/html/screenshot/*)."""

from __future__ import annotations

import base64
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
# misp_standard: return an image MISPObject with the PNG attached (rendered inline
# in MISP) instead of a text description.
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.2",
    "author": "RST Cloud",
    "description": "Capture a page screenshot (first/full/last frame) of a URL/IP target via RST Scan API.",
    "module-type": ["expansion"],
    "name": "RST Cloud Screenshot",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Renders the target page and returns a PNG screenshot as an image MISP "
        "object (inline in MISP). Configurable frame: first, full (default), or last."
    ),
    "references": ["https://api.rstcloud.net/", "https://pypi.org/project/rstapi/"],
    "input": "URL, domain, hostname, or IP attribute (optional port via config).",
    "output": "image MISP object with PNG attachment linked to the enriched attribute.",
}
# 'frame' selects which screenshot endpoint to call (first/full/last, default full).
# 'port' (optional): override default port 443.
moduleconfig = ["api_key", "base_url", "frame", "port", "timeout"]

_FRAMES = {
    "first": "GetHtmlScreenshotFirst",
    "full": "GetHtmlScreenshotFull",
    "last": "GetHtmlScreenshotLast",
}


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

    method = _FRAMES.get((config.get("frame") or "full").lower(), "GetHtmlScreenshotFull")
    data, err = unwrap(getattr(rstapi.scan(**scan_kwargs(config)), method)(target))
    if err:
        return error(f"RST screenshot failed: {err}")

    b64 = data.get("image_base64") if isinstance(data, dict) else None
    try:
        raw = base64.b64decode(b64) if b64 else None
    except Exception:
        raw = None
    if not raw:
        return text_result(f"{target}: no screenshot returned ({method})", "RST Screenshot")

    from pymisp import MISPObject

    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)
    image = MISPObject("image")
    image.add_attribute("attachment", value="screenshot.png", data=BytesIO(raw))
    image.comment = f"RST Screenshot ({method})"
    event.add_attribute("link", f"https://{target}" if "://" not in target else target,
                        comment=f"RST Screenshot source ({method})", to_ids=False)
    if anchor:
        image.add_reference(anchor, "screenshot-of")
    event.add_object(image)
    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
