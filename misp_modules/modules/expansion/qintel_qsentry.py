import json
import logging

from pymisp import MISPAttribute, MISPEvent, MISPObject, MISPTag
from qintel_helper import search_qsentry

from . import check_input_attribute, checking_error, standard_error_message

logger = logging.getLogger("qintel_qsentry")
logger.setLevel(logging.DEBUG)

moduleinfo = {
    "version": "1.0",
    "author": "Qintel, LLC",
    "description": "A hover and expansion module which queries Qintel QSentry for ip reputation data",
    "module-type": ["hover", "expansion"],
    "name": "Qintel QSentry Lookup",
    "logo": "qintel.png",
    "requirements": ["A Qintel API token"],
    "features": (
        "This module takes an ip-address (ip-src or ip-dst) attribute as input, and queries the Qintel QSentry API to"
        " retrieve ip reputation data"
    ),
    "references": ["https://www.qintel.com/products/qsentry/"],
    "input": "ip address attribute",
    "output": "",
    "ouput": (
        "Objects containing the enriched IP, threat tags, last seen attributes and associated Autonomous System"
        " information"
    ),
}

moduleconfig = ["token", "remote"]

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst"],
    "output": ["ip-src", "ip-dst", "AS", "freetext"],
    "format": "misp_standard",
}

TAG_COLOR = {"benign": "#27ae60", "suspicious": "#e6a902", "malicious": "#c0392b"}

CLIENT_HEADERS = {
    "User-Agent": f"MISP/{moduleinfo['version']}",
}


def _return_error(message):
    misperrors["error"] = message
    return misperrors


def _make_tags(enriched_attr, result):

    for tag in result["tags"]:
        color = TAG_COLOR["suspicious"]
        if tag == "criminal":
            color = TAG_COLOR["malicious"]

        t = MISPTag()
        t.from_dict(**{"name": f'qintel:tag="{tag}"', "colour": color})
        enriched_attr.add_tag(**t)

    return enriched_attr


def _make_enriched_attr(event, result, orig_attr):

    enriched_object = MISPObject("Qintel Threat Enrichment")
    enriched_object.add_reference(orig_attr.uuid, "related-to")

    enriched_attr = MISPAttribute()
    enriched_attr.from_dict(
        **{
            "value": orig_attr.value,
            "type": orig_attr.type,
            "distribution": 0,
            "object_relation": "enriched-attr",
            "to_ids": orig_attr.to_ids,
        }
    )

    enriched_attr = _make_tags(enriched_attr, result)
    enriched_object.add_attribute(**enriched_attr)

    comment_attr = MISPAttribute()
    comment_attr.from_dict(
        **{
            "value": "\n".join(result.get("descriptions", [])),
            "type": "text",
            "object_relation": "descriptions",
            "distribution": 0,
        }
    )
    enriched_object.add_attribute(**comment_attr)

    last_seen = MISPAttribute()
    last_seen.from_dict(
        **{
            "value": result.get("last_seen"),
            "type": "datetime",
            "object_relation": "last-seen",
            "distribution": 0,
        }
    )
    enriched_object.add_attribute(**last_seen)

    event.add_attribute(**orig_attr)
    event.add_object(**enriched_object)

    return event


def _make_asn_attr(event, result, orig_attr):

    asn_object = MISPObject("asn")
    asn_object.add_reference(orig_attr.uuid, "related-to")

    asn_attr = MISPAttribute()
    asn_attr.from_dict(
        **{
            "type": "AS",
            "value": result.get("asn"),
            "object_relation": "asn",
            "distribution": 0,
        }
    )
    asn_object.add_attribute(**asn_attr)

    org_attr = MISPAttribute()
    org_attr.from_dict(
        **{
            "type": "text",
            "value": result.get("asn_name", "unknown").title(),
            "object_relation": "description",
            "distribution": 0,
        }
    )
    asn_object.add_attribute(**org_attr)

    event.add_object(**asn_object)

    return event


def _format_hover(event, result):

    enriched_object = event.get_objects_by_name("Qintel Threat Enrichment")[0]

    tags = ", ".join(result.get("tags"))
    enriched_object.add_attribute("Tags", type="text", value=tags)

    return event


def _format_result(attribute, result):

    event = MISPEvent()

    orig_attr = MISPAttribute()
    orig_attr.from_dict(**attribute)

    event = _make_enriched_attr(event, result, orig_attr)
    event = _make_asn_attr(event, result, orig_attr)

    return event


def _check_config(config):
    if not config:
        return False

    if not isinstance(config, dict):
        return False

    if config.get("token", "") == "":
        return False

    return True


def _check_request(request):
    if not request.get("attribute"):
        return f"{standard_error_message}, {checking_error}"

    check_reqs = ("type", "value")
    if not check_input_attribute(request["attribute"], requirements=check_reqs):
        return f"{standard_error_message}, {checking_error}"

    if request["attribute"]["type"] not in mispattributes["input"]:
        return "Unsupported attribute type"


def handler(q=False):
    if not q:
        return False

    request = json.loads(q)
    config = request.get("config")

    if not _check_config(config):
        return _return_error("Missing Qintel token")

    check_request_error = _check_request(request)
    if check_request_error:
        return _return_error(check_request_error)

    search_args = {"token": config["token"], "remote": config.get("remote")}

    try:
        result = search_qsentry(request["attribute"]["value"], **search_args)
    except Exception as e:
        return _return_error(str(e))

    event = _format_result(request["attribute"], result)
    if not request.get("event_id"):
        event = _format_hover(event, result)

    event = json.loads(event.to_json())

    ret_result = {key: event[key] for key in ("Attribute", "Object") if key in event}
    return {"results": ret_result}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
