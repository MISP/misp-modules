"""rst_ssl — SSL certificate as a pivotable x509 object (GET /scan/ssl/certificate)."""

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

_INPUTS = ["ip-dst", "ip-src", "hostname", "domain",
           "ip-dst|port", "ip-src|port", "hostname|port", "domain|port"]
# misp_standard: return a real x509 MISPObject (searchable subject/issuer,
# pivotable fingerprints) instead of a text blob.
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.2",
    "author": "RST Cloud",
    "description": "Fetch the SSL certificate for an IP[:port] as an x509 object via RST Scan API.",
    "module-type": ["expansion"],
    "name": "RST Cloud SSL Certificate",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Connects to the target service and retrieves the TLS certificate via "
        "RST Scan GET /scan/ssl/certificate. Returns an x509 MISP object with "
        "pivotable fingerprints (SHA-1/256/MD5), subject, issuer, and validity dates."
    ),
    "references": ["https://api.rstcloud.net/", "https://pypi.org/project/rstapi/"],
    "input": "IP, hostname, or domain attribute (optional port via config or composite).",
    "output": "x509 MISP object referencing the enriched attribute.",
}
# 'port' (optional): TLS port to scan when the attribute carries none (API
# defaults to 443 if omitted).
moduleconfig = ["api_key", "base_url", "port", "timeout"]

# RST certificate field -> x509 object_relation (pymisp infers the attribute type
# from the template, so fingerprints become pivotable x509-fingerprint-* types).
_X509_MAP = {
    "subject_dn": "subject",
    "issuer_dn": "issuer",
    "serial_number": "serial-number",
    "version": "version",
    "not_before": "validity-not-before",
    "not_after": "validity-not-after",
    "fingerprint_sha1": "x509-fingerprint-sha1",
    "fingerprint_sha256": "x509-fingerprint-sha256",
    "fingerprint_md5": "x509-fingerprint-md5",
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
    config = request.get("config")
    if not rst_kwargs(config)["APIKEY"]:
        return error("An RST Cloud API key is required (set api_key in the module config).")
    target = scan_target(request, _INPUTS, config, default_port=443)
    if not target:
        return error("No target found in the request (expects an IP/hostname).")

    data, err = unwrap(rstapi.scan(**scan_kwargs(config)).GetSslCertificate(target))
    if err:
        return error(f"RST SSL scan failed: {err}")
    if not isinstance(data, dict) or not data.get("subject_dn"):
        return text_result(f"{target}: no certificate returned", "RST SSL Certificate")

    from pymisp import MISPObject

    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)
    x509 = MISPObject("x509")
    for field, relation in _X509_MAP.items():
        if data.get(field):
            x509.add_attribute(relation, value=data[field])
    x509.comment = f"RST SSL Certificate for {target}"
    if anchor:
        x509.add_reference(anchor, "identifies")
    event.add_object(x509)
    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
