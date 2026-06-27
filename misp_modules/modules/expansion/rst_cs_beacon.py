"""rst_cs_beacon — scan for Cobalt Strike beacon (GET /scan/cs-beacon)."""

from __future__ import annotations

import json

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

_INPUTS = [
    "ip-dst",
    "ip-src",
    "url",
    "domain",
    "hostname",
    "ip-dst|port",
    "ip-src|port",
    "hostname|port",
    "domain|port",
]
# misp_standard: on a hit, return the beacon blob sha256(s) as pivotable
# attributes tagged to the Cobalt Strike galaxy.
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.2",
    "author": "RST Cloud",
    "description": (
        "Scan a target IP[:port] for a Cobalt Strike beacon configuration"
        " via RST Scan API."
    ),
    "module-type": ["expansion"],
    "name": "RST Cloud Cobalt Strike Beacon",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Probes the target for Cobalt Strike beacon configurations via RST"
        " Scan GET /scan/cs-beacon. On a hit, returns file MISP object(s)"
        " with pivotable SHA-256 hashes tagged to the Cobalt Strike"
        " galaxy."
    ),
    "references": [
        "https://api.rstcloud.net/",
        "https://pypi.org/project/rstapi/",
    ],
    "input": (
        "IP, URL, domain, or hostname attribute (optional port via config)."
    ),
    "output": (
        "file MISP object(s) with beacon hashes and Cobalt Strike galaxy tag."
    ),
}
# 'port' (optional): port to probe when the attribute carries none
# (default 443).
moduleconfig = ["api_key", "base_url", "port", "timeout"]

_CS_TAG = 'misp-galaxy:tool="Cobalt Strike"'


def _arch(node):
    return node if isinstance(node, dict) else {}


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


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
    target = scan_target(request, _INPUTS, config, default_port=443)
    if not target:
        return error("No target found in the request.")

    data, err = unwrap(rstapi.scan(**scan_kwargs(config)).GetCsBeacon(target))
    if err:
        return error(f"RST CS beacon scan failed: {err}")
    if not isinstance(data, dict) or not data:
        return text_result(
            f"{target}: no Cobalt Strike beacon found", "RST CS Beacon"
        )

    # The scanner ALWAYS returns x86/x64 probe blocks; an actual beacon is only
    # present when a block carries a parsed `config` (or a non-zero `size`). An
    # empty config / size 0 means "probed, nothing found" — NOT a detection.
    blocks = {"x86": _arch(data.get("x86")), "x64": _arch(data.get("x64"))}
    hits = {
        arch: b
        for arch, b in blocks.items()
        if b.get("config") or _to_int(b.get("size")) > 0
    }
    if not hits:
        return text_result(
            f"{target}: no Cobalt Strike beacon detected", "RST CS Beacon"
        )

    from pymisp import MISPObject

    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    seen = set()
    for arch, block in hits.items():
        sha = block.get("sha256")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        # The beacon payload is a file; group its hash + config as a file
        # object so the detection is tied to the scanned host, not a loose
        # sha256.
        fobj = MISPObject("file")
        sha_attr = fobj.add_attribute("sha256", value=sha)
        sha_attr.add_tag(_CS_TAG)  # tags attach to attributes, not objects
        if block.get("md5"):
            fobj.add_attribute("md5", value=block["md5"])
        if block.get("size"):
            fobj.add_attribute("size-in-bytes", value=block["size"])
        cfg = block.get("config") or {}
        fobj.add_attribute(
            "text",
            value=(
                f"Cobalt Strike beacon ({arch}) on {target}; "
                f"config: {json.dumps(cfg)[:400]}"
            ),
        )
        fobj.comment = "RST CS Beacon"
        if anchor:
            fobj.add_reference(anchor, "characterizes")
        event.add_object(fobj)
    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
