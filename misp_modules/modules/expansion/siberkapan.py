import json

import requests

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"],
    "output": ["text"],
}
moduleinfo = {
    "version": "1.0",
    "author": "Oktay Alver",
    "description": "Hover and expansion module to look up an IP address in SiberKapan threat intelligence.",
    "module-type": ["hover", "expansion"],
    "name": "SiberKapan Lookup",
    "logo": "",
    "requirements": [],
    "features": (
        "Queries the public SiberKapan API (no API key required) and returns the threat score, "
        "the background noise score and class (mass scanning, focused, opportunistic), the breadth "
        "of activity across SiberKapan sensors (sensors, ports, active days in the last 90 days), "
        "observed attack types, first and last seen dates, ASN and country."
    ),
    "references": ["https://siberkapan.org", "https://siberkapan.org/methodology"],
    "input": "An IP address attribute (ip-src, ip-dst, ip-src|port, ip-dst|port).",
    "output": "Text describing the SiberKapan record for the IP address.",
    "data-source": "external",
}
moduleconfig = []

API_URL = "https://siberkapan.org/api/v1/ip/{}"
CLASS_LABELS = {"mass": "mass scanning", "focused": "focused", "opportunistic": "opportunistic"}


def _get_value(request):
    attribute = request.get("attribute") or {}
    if attribute.get("value"):
        return attribute["value"]
    for attr_type in mispattributes["input"]:
        if request.get(attr_type):
            return request[attr_type]
    return None


def _format_asn(asn, org):
    asn = str(asn).strip()
    if not asn.upper().startswith("AS"):
        asn = f"AS{asn}"
    return f"ASN: {asn} {org or ''}".strip()


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    value = _get_value(request)
    if not value:
        misperrors["error"] = "Missing IP address"
        return misperrors
    ip = value.split("|")[0].strip()

    try:
        response = requests.get(
            API_URL.format(ip),
            timeout=10,
            headers={"User-Agent": "misp-modules-siberkapan/1.0"},
        )
    except requests.RequestException as e:
        misperrors["error"] = f"SiberKapan API unreachable: {e}"
        return misperrors

    if response.status_code == 404:
        return {"results": [{"types": ["text"], "values": [f"{ip} is not listed in SiberKapan"]}]}
    if response.status_code != 200:
        misperrors["error"] = f"SiberKapan API returned HTTP {response.status_code}"
        return misperrors

    data = response.json()
    lines = [f"SiberKapan threat score: {data.get('score')}/100"]
    noise = data.get("noise")
    if noise:
        lines.append(
            f"Background noise: {noise.get('noise_score')}/100 "
            f"({CLASS_LABELS.get(noise.get('noise_class'), noise.get('noise_class'))}), "
            f"{noise.get('sensors')} sensors, {noise.get('ports')} ports, "
            f"{noise.get('active_days')} active days in the last 90 days"
        )
    if data.get("attack_types"):
        lines.append("Attack types: " + ", ".join(sorted(data["attack_types"])))
    if data.get("sources"):
        lines.append("Observed by: " + ", ".join(sorted(data["sources"])))
    lines.append(f"First seen: {data.get('first_seen')} / Last seen: {data.get('last_seen')}")
    if data.get("asn"):
        lines.append(_format_asn(data["asn"], data.get("asn_org")))
    if data.get("country_code"):
        lines.append(f"Country: {data.get('country_code')}")
    if data.get("siberkapan_url"):
        lines.append(f"Details: {data['siberkapan_url']}")
    return {"results": [{"types": ["text"], "values": lines}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
