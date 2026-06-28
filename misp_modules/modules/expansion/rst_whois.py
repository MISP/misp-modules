"""rst_whois — parsed WHOIS as whois object (GET /whois/{domain})."""

from __future__ import annotations

import json

import rstapi

from ._rstcloud.client import (
    error,
    misp_event_with_source,
    rst_kwargs,
    scan_group,
    standard_results,
    text_result,
    unwrap,
    value_from_request,
)

misperrors = {"error": "Error"}

_INPUTS = ["domain", "hostname"]
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.2",
    "author": "RST Cloud",
    "description": (
        "Retrieve parsed WHOIS information for a domain via RST Cloud."
    ),
    "module-type": ["expansion", "hover"],
    "name": "RST Cloud Whois",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Queries RST Cloud GET /whois for parsed domain registration data."
        " Returns a standard whois MISP object (registrar, registrant,"
        " dates, nameservers) linked back to the enriched attribute."
    ),
    "references": [
        "https://api.rstcloud.net/",
        "https://pypi.org/project/rstapi/",
    ],
    "input": "Domain or hostname attribute.",
    "output": "whois MISP object with registration and nameserver fields.",
}
moduleconfig = ["api_key", "base_url"]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _known(v) -> bool:
    """True when a value is present and not a placeholder like 'unknown'."""
    return bool(v) and str(v).strip().lower() not in (
        "unknown",
        "none",
        "",
        "null",
        "n/a",
    )


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
    domain = value_from_request(request, _INPUTS)
    if not domain:
        return error("No domain found in the request.")

    data, err = unwrap(
        rstapi.whoisapi(**rst_kwargs(config)).GetDomainInfo(domain)
    )
    if err:
        return error(f"RST Whois API lookup failed: {err}")
    if not isinstance(data, dict):
        return text_result(f"{domain}: no WHOIS data found", "RST Whois API")

    from pymisp import MISPObject

    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    obj = MISPObject("whois")
    obj.comment = f"RST Whois API lookup for {domain}"

    # Identity
    if _known(data.get("domain")):
        obj.add_attribute("domain", value=data["domain"], to_ids=False)
    if _known(data.get("registrar")):
        obj.add_attribute("registrar", value=data["registrar"], to_ids=False)
    if _known(data.get("registrant")):
        obj.add_attribute(
            "registrant-name", value=data["registrant"], to_ids=False
        )
    if _known(data.get("registrant_org")):
        obj.add_attribute(
            "registrant-org", value=data["registrant_org"], to_ids=False
        )
    if _known(data.get("registrant_email")):
        obj.add_attribute(
            "registrant-email",
            value=data["registrant_email"],
            to_ids=False,
        )

    # Dates  (API returns "created_on" / "updated_on" / "expires_on")
    if _known(data.get("created_on")):
        obj.add_attribute(
            "creation-date", value=data["created_on"], to_ids=False
        )
    if _known(data.get("updated_on")):
        obj.add_attribute(
            "modification-date", value=data["updated_on"], to_ids=False
        )
    if _known(data.get("expires_on")):
        obj.add_attribute(
            "expiration-date", value=data["expires_on"], to_ids=False
        )

    # Nameservers — one attribute per NS
    for ns in (data.get("nameservers") or "").split(","):
        ns = ns.strip()
        if ns:
            obj.add_attribute("nameserver", value=ns, to_ids=False)

    # Domain age + status as a free-text note (no dedicated whois relation)
    notes = []
    if data.get("age") is not None:
        notes.append(f"age: {data['age']} days")
    if _known(data.get("status")):
        notes.append(f"status: {data['status']}")
    if notes:
        obj.add_attribute("text", value="; ".join(notes), to_ids=False)

    if anchor:
        obj.add_reference(anchor, "related-to")
    event.add_object(obj)
    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
