"""rst_favicon — favicon hashes as a file object (GET /scan/favicon)."""

from __future__ import annotations

import base64
import json
from io import BytesIO

import rstapi

from ._rstcloud.client import (
    error,
    host_only,
    misp_event_with_source,
    rst_kwargs,
    scan_group,
    scan_kwargs,
    standard_results,
    text_result,
    unwrap,
    value_from_request,
)

misperrors = {"error": "Error"}

_INPUTS = [
    "url",
    "domain",
    "hostname",
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "hostname|port",
    "domain|port",
]
# misp_standard: file object (md5/sha1/sha256 pivotable in Netlas/Censys)
# plus a standalone favicon_hash attribute (Murmur3/MMH3, Shodan/FOFA).
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.3",
    "author": "RST Cloud",
    "description": (
        "Fetch a target's favicon (image + all hashes for"
        " Shodan/Netlas/Censys pivoting) via RST Scan API."
    ),
    "module-type": ["expansion"],
    "name": "RST Cloud Favicon",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Retrieves the favicon image and cryptographic hashes via RST Scan"
        " GET /scan/favicon. Returns a file MISP object with"
        " MD5/SHA-1/SHA-256 for Censys/Netlas pivoting and a standalone"
        " Murmur3 favicon-hash attribute for Shodan/FOFA-style pivoting."
    ),
    "references": [
        "https://api.rstcloud.net/",
        "https://pypi.org/project/rstapi/",
    ],
    "input": "URL, domain, hostname, or IP attribute.",
    "output": (
        "file MISP object, favicon-hash attribute, and resolved favicon URL."
    ),
}
moduleconfig = ["api_key", "base_url", "timeout"]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config")
    if not rst_kwargs(config)["APIKEY"]:
        return error(
            "An RST Cloud API key is required (set api_key in the module"
            " config)."
        )
    # Favicon endpoint expects a bare host or a full URL — never host:port.
    # The API fetches the page over HTTP/HTTPS itself; adding ":443" breaks it.
    raw = value_from_request(request, _INPUTS)
    if not raw:
        return error("No target found in the request.")
    target = raw if raw.startswith(("http://", "https://")) else host_only(raw)

    data, err = unwrap(
        rstapi.scan(**scan_kwargs(config)).GetFavicon(
            target, include_base64=True
        )
    )
    if err:
        return error(f"RST favicon scan failed: {err}")
    if not isinstance(data, dict) or not data.get("favicon_hash"):
        return text_result(f"{target}: no favicon returned", "RST Favicon")

    from pymisp import MISPObject

    fhash = str(data["favicon_hash"])
    req_loc = data.get("req_location") or ""
    content_type = data.get("req_content_type") or "image/x-icon"

    # Real filename from the resolved favicon URL (e.g. "drive_2026_32dp.ico")
    raw_fname = (
        req_loc.rstrip("/").split("/")[-1].split("?")[0] if req_loc else ""
    )
    fname = raw_fname if (raw_fname and "." in raw_fname) else "favicon.ico"

    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    # file object: standard hashes (md5/sha1/sha256) are auto-correlated and
    # indexed for pivoting in Netlas, Censys, and other threat-intel platforms.
    fobj = MISPObject("file")
    fobj.add_attribute("filename", value=fname)
    fobj.add_attribute("mimetype", value=content_type)
    for htype in ("md5", "sha1", "sha256"):
        if data.get(htype):
            fobj.add_attribute(htype, value=data[htype])

    # Attach the raw image when the API returned base64
    try:
        raw = (
            base64.b64decode(data["base64_image"])
            if data.get("base64_image")
            else None
        )
    except Exception:
        raw = None
    if raw:
        fobj.add_attribute("attachment", value=fname, data=BytesIO(raw))

    fobj.comment = "RST Favicon"
    if anchor:
        fobj.add_reference(anchor, "identifies")
    event.add_object(fobj)

    # Resolved favicon URL — where the image actually lives after redirects
    if req_loc:
        event.add_attribute(
            "link",
            req_loc,
            comment="RST Favicon resolved URL",
            to_ids=False,
        )

    # favicon_hash (Murmur3/MMH3): standalone attribute for independent
    # correlation across events and Shodan/FOFA-style hunting workflows.
    fav_attr = event.add_attribute(
        "other",
        fhash,
        comment=f"Murmur3 favicon hash for {target} (Shodan/FOFA pivot)",
        to_ids=False,
    )
    fav_attr.add_tag(f'rstcloud:favicon:hash="{fhash}"')

    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
