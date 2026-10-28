import ipaddress
import json

import pycountry
import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-dst", "ip-src"], "format": "misp_standard"}
moduleinfo = {
    "version": "2.2",
    "author": "Shivam Sandbhor <shivam@crowdsec.net>",
    "description": "Module to access CrowdSec CTI API.",
    "module-type": ["hover", "expansion"],
    "name": "CrowdSec CTI",
    "logo": "crowdsec.png",
    "requirements": [
        "A CrowdSec CTI API key. Get yours by following"
        " https://docs.crowdsec.net/docs/cti_api/getting_started/#getting-an-api-key"
    ],
    "features": (
        "Look up IPv4 and IPv6 addresses using the CrowdSec CTI API. Results include background noise score,"
        " classifications, false-positive categories, reputation, behaviors, MITRE ATT&CK techniques, CVEs and scores"
        " over time when available. Each tag category can be enabled or disabled in the module configuration."
    ),
    "references": [
        "https://www.crowdsec.net/",
        "https://docs.crowdsec.net/docs/cti_api/getting_started",
        "https://app.crowdsec.net/",
    ],
    "input": "An IP address.",
    "output": "IP Lookup information from CrowdSec CTI API",
}
moduleconfig = [
    "api_key",
    "add_reputation_tag",
    "add_behavior_tag",
    "add_classification_tag",
    "add_mitre_technique_tag",
    "add_cve_tag",
]


def handler(q=False):
    if q is False:
        return False

    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid CrowdSec request: expected a JSON object"}
    if not isinstance(request, dict):
        return {"error": "Invalid CrowdSec request: expected a JSON object"}
    if not isinstance(request.get("config"), dict) or not request["config"]:
        return {"error": "Missing CrowdSec Config"}

    if not request["config"].get("api_key"):
        return {"error": "Missing CrowdSec API key"}

    if not isinstance(request.get("attribute"), dict) or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}

    if request["attribute"].get("type") not in mispattributes["input"]:
        return {"error": f"Wrong input type. Please choose one of the following: {', '.join(mispattributes['input'])}"}

    return _handler_v2(request)


def _get_boolean_config(request_data, config: str, default_config: bool):
    if request_data["config"].get(config) is None:
        return default_config
    raw_config = str(request_data["config"][config]).strip().lower()
    # falsy values, return False
    if raw_config in ["false", "0", "no", "off"]:
        return False
    # truthy values, return True
    if raw_config in ["true", "1", "yes", "on"]:
        return True
    return default_config


def _handler_v2(request_data):
    attribute = request_data["attribute"]
    ip = attribute["value"]
    # Validate IP
    try:
        if not isinstance(ip, str) or "%" in ip:
            raise ValueError
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"IP ({ip}) is not valid for calling CrowdSec CTI. Please provide a valid IP address."}

    try:
        response = requests.get(
            f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
            headers={
                "x-api-key": request_data["config"]["api_key"],
                "User-Agent": f"crowdsec-misp/v{moduleinfo['version']}",
            },
            timeout=30,
            allow_redirects=False,
        )
    except requests.RequestException:
        return {"error": "Unable to reach the CrowdSec CTI API"}
    if response.status_code != 200:
        return {"error": f"CrowdSec CTI API returned HTTP {response.status_code}"}
    try:
        crowdsec_cti = response.json()
    except ValueError:
        return {"error": "Invalid JSON response from the CrowdSec CTI API"}
    if not isinstance(crowdsec_cti, dict) or not crowdsec_cti.get("ip"):
        return {"error": "Invalid IP lookup response from the CrowdSec CTI API"}

    add_reputation_tag = _get_boolean_config(request_data, "add_reputation_tag", True)
    add_behavior_tag = _get_boolean_config(request_data, "add_behavior_tag", True)
    add_classification_tag = _get_boolean_config(request_data, "add_classification_tag", True)
    add_mitre_technique_tag = _get_boolean_config(request_data, "add_mitre_technique_tag", True)
    add_cve_tag = _get_boolean_config(request_data, "add_cve_tag", True)

    misp_event = MISPEvent()
    misp_attribute = misp_event.add_attribute(**attribute)
    crowdsec_context_object = MISPObject("crowdsec-ip-context")
    history = crowdsec_cti.get("history") or {}
    crowdsec_context_object.from_dict(**{key: history[key] for key in ("first_seen", "last_seen") if history.get(key)})
    ip_attribute = crowdsec_context_object.add_attribute("ip", crowdsec_cti["ip"])
    reputation = crowdsec_cti.get("reputation") or "unknown"
    crowdsec_context_object.add_attribute("reputation", reputation)
    if add_reputation_tag:
        tag = f'crowdsec:reputation="{reputation}"'
        ip_attribute.add_tag(tag)
    for field, relation in (
        ("ip_range", "ip-range"),
        ("ip_range_score", "ip-range-score"),
        ("as_name", "as-name"),
        ("as_num", "as-num"),
        ("reverse_dns", "reverse-dns"),
        ("background_noise_score", "background-noise"),
    ):
        value = crowdsec_cti.get(field)
        if value is not None and value != "":
            crowdsec_context_object.add_attribute(relation, value)
    location = crowdsec_cti.get("location") or {}
    country = get_country_name_from_alpha_2(location.get("country"))
    if country:
        crowdsec_context_object.add_attribute("country", country)
    for field, relation in (
        ("country", "country-code"),
        ("city", "city"),
        ("latitude", "latitude"),
        ("longitude", "longitude"),
    ):
        value = location.get(field)
        if value is not None and value != "":
            crowdsec_context_object.add_attribute(relation, value)
    for behavior in crowdsec_cti.get("behaviors") or []:
        crowdsec_context_object.add_attribute("behaviors", behavior["label"], comment=behavior["description"])
        if add_behavior_tag:
            name = behavior["name"].replace(":", "-")
            tag = f'crowdsec:behavior="{name}"'
            ip_attribute.add_tag(tag)
    for technique in crowdsec_cti.get("mitre_techniques") or []:
        technique_name = technique["name"]
        mitre_url = (
            f"https://attack.mitre.org/tactics/{technique_name}"
            if technique_name.startswith("TA")
            else f"https://attack.mitre.org/techniques/{technique_name.replace('.', '/')}"
        )
        crowdsec_context_object.add_attribute(
            "mitre-techniques",
            technique["label"],
            comment=f'{technique["description"]} ({mitre_url})',
        )
        if add_mitre_technique_tag:
            tag = f'crowdsec:mitre-technique="{technique_name}"'
            ip_attribute.add_tag(tag)

    for cve in crowdsec_cti.get("cves") or []:
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        crowdsec_context_object.add_attribute("cves", cve, comment=cve_url)
        if add_cve_tag:
            tag = f'crowdsec:cve="{cve}"'
            ip_attribute.add_tag(tag)

    classifications = crowdsec_cti.get("classifications") or {}
    # The API uses underscores; the MISP object and taxonomy use hyphens.
    for feature, relation, predicate in (
        ("false_positives", "false-positives", "false-positive"),
        ("classifications", "classifications", "classification"),
    ):
        for value in classifications.get(feature) or []:
            crowdsec_context_object.add_attribute(relation, value["label"], comment=value["description"])
            if add_classification_tag:
                name = value["name"].replace(":", "-")
                tag = f'crowdsec:{predicate}="{name}"'
                ip_attribute.add_tag(tag)
    if crowdsec_cti.get("attack_details"):
        crowdsec_context_object.add_attribute(
            "attack-details",
            ", ".join(
                f"{scenario['name']} - {scenario['label']} ({scenario['description']})"
                for scenario in crowdsec_cti["attack_details"]
            ),
        )
    target_countries = filter(None, map(get_country_name_from_alpha_2, crowdsec_cti.get("target_countries") or {}))
    target_countries = ", ".join(target_countries)
    if target_countries:
        crowdsec_context_object.add_attribute("target-countries", target_countries)
    api_scores = crowdsec_cti.get("scores") or {}
    trust = (api_scores.get("overall") or {}).get("trust")
    if trust is not None:
        crowdsec_context_object.add_attribute("trust", trust)
    scores = []
    for time_period, indicators in api_scores.items():
        if not indicators:
            continue
        tp = " ".join(map(str.capitalize, time_period.split("_")))
        indicator = (
            f"{indicator_type.capitalize()}: {indicator_value}"
            for indicator_type, indicator_value in indicators.items()
        )
        scores.append(f"{tp}: {' - '.join(indicator)}")
    if scores:
        crowdsec_context_object.add_attribute("scores", ", ".join(scores))
    crowdsec_context_object.add_reference(misp_attribute.uuid, "related-to")
    misp_event.add_object(crowdsec_context_object)

    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
    return {"results": results}


def get_country_name_from_alpha_2(alpha_2):
    if not alpha_2:
        return None
    country_info = pycountry.countries.get(alpha_2=alpha_2)
    return country_info.name if country_info else None


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
