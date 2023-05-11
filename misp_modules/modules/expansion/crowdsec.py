import json

from pymisp import MISPEvent, MISPObject
import pycountry
import requests

mispattributes = {"input": ["ip-dst", "ip-src"], "output": ["text"], 'format': 'misp_standard'}
moduleinfo = {
    "version": "1.0",
    "author": "Shivam Sandbhor <shivam@crowdsec.net>",
    "description": "Module to access CrowdSec CTI API.",
    "module-type": ["hover", "expansion"],
}
moduleconfig = ["api_key", "api_version"]


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    if not request.get("config"):
        return {"error": "Missing CrowdSec Config"}

    if not request["config"].get("api_key"):
        return {"error": "Missing CrowdSec API key"}

    request["config"]["api_version"] = "v2"

    if request["config"]["api_version"] == "v2":
        return _handler_v2(request)
    return {"error": f'API version {request["config"]["api_version"]} not supported'}


def _handler_v2(request_data):
    if request_data.get("ip-dst"):
        ip = request_data.get("ip-dst")
    elif request_data.get("ip-src"):
        ip = request_data.get("ip-src")

    crowdsec_cti = requests.get(
        f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
        headers={
        "x-api-key": request_data["config"]["api_key"],
        "User-Agent": "crowdsec-misp/v1.0.0",
        },
    )
    crowdsec_cti.raise_for_status()
    crowdsec_cti = crowdsec_cti.json()

    misp_event = MISPEvent()
    crowdsec_context_object = MISPObject("crowdsec-ip-context")
    crowdsec_context_object.add_attribute("IP Address", **{"type": "text", "value": ip})
    crowdsec_context_object.add_attribute(
        "IP Range", **{"type": "text", "value": crowdsec_cti["ip_range"]}
    )
    crowdsec_context_object.add_attribute(
        "IP Range Score", **{"type": "text", "value": crowdsec_cti["ip_range_score"]}
    )
    crowdsec_context_object.add_attribute(
        "Country",
        **{
            "type": "text",
            "value": get_country_name_from_alpha_2(crowdsec_cti["location"]["country"]),
        },
    )
    if crowdsec_cti["location"]["city"]:
        crowdsec_context_object.add_attribute(
            "City", **{"type": "text", "value": crowdsec_cti["location"]["city"]}
        )

    crowdsec_context_object.add_attribute(
        "Latitude", **{"type": "float", "value": crowdsec_cti["location"]["latitude"]}
    )
    crowdsec_context_object.add_attribute(
        "Longitude", **{"type": "float", "value": crowdsec_cti["location"]["longitude"]}
    )

    crowdsec_context_object.add_attribute(
        "AS Name", **{"type": "text", "value": crowdsec_cti["as_name"]}
    )

    crowdsec_context_object.add_attribute(
        "AS Number", **{"type": "AS", "value": crowdsec_cti["as_num"]}
    )

    crowdsec_context_object.add_attribute(
        "Reverse DNS", **{"type": "domain", "value": crowdsec_cti["reverse_dns"]}
    )

    crowdsec_context_object.add_attribute(
        "Attack Categories",
        **{
            "type": "text",
            "value": ",".join(
                [attack_category["label"] for attack_category in crowdsec_cti["behaviors"]]
            ),
        },
    )

    crowdsec_context_object.add_attribute(
        "Triggered Scenarios",
        **{
            "type": "text",
            "value": ",".join([scenario["name"] for scenario in crowdsec_cti["attack_details"]]),
        },
    )

    crowdsec_context_object.add_attribute(
        "Top 10 Target Countries",
        **{
            "type": "float",
            "value": ",".join(
                map(get_country_name_from_alpha_2, crowdsec_cti["target_countries"].keys())
            ),
        },
    )

    crowdsec_context_object.add_attribute(
        "Trust", **{"type": "float", "value": crowdsec_cti["scores"]["overall"]["trust"]}
    )

    crowdsec_context_object.add_attribute(
        "First Seen", **{"type": "datetime", "value": crowdsec_cti["history"]["first_seen"]}
    )

    crowdsec_context_object.add_attribute(
        "Last Seen", **{"type": "datetime", "value": crowdsec_cti["history"]["last_seen"]}
    )

    for time_period, indicators in crowdsec_cti["scores"].items():
        tp = " ".join(map(str.capitalize, time_period.split("_")))

        for indicator_type, indicator_value in indicators.items():
            crowdsec_context_object.add_attribute(
                f"{tp} {indicator_type.capitalize()}", **{"type": "float", "value": indicator_value}
            )

    misp_event.add_object(crowdsec_context_object)

    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
    return {"results": results}


def get_country_name_from_alpha_2(alpha_2):
    country_info = pycountry.countries.get(alpha_2=alpha_2)
    return country_info.name


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
