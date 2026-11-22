"""Look up an IP attribute in the Offensive Agency host API."""

import json
from uuid import UUID

import requests
from pymisp.exceptions import PyMISPError

from misp_modules.lib.gathering import stable_uuid
from misp_modules.lib.offensive_agency import SOURCE, fetch, host_ip, host_objects, reference

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "name": "Offensive Agency Lookup",
    "version": "1.0",
    "author": "MISP Project",
    "module-type": ["expansion"],
    "data-source": "external",
    "description": "Look up an IP address in Offensive Agency's ONYPHE observations.",
    "requirements": ["requests", "PyMISP"],
    "references": [SOURCE, SOURCE + "about"],
    "input": "An ip-src or ip-dst attribute.",
    "output": "A dated observation, related domain-ip and ip-port objects, and the original host JSON.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        attribute = request["attribute"]
        if attribute["type"] not in mispattributes["input"]:
            return {"error": "Expected an ip-src or ip-dst attribute"}
        ip = host_ip(attribute["value"])
        attribute_uuid = str(UUID(attribute["uuid"]))
    except (AttributeError, KeyError, TypeError, ValueError):
        return {"error": "Expected an IP attribute with a valid address and UUID"}

    try:
        with requests.Session() as session:
            session.headers["User-Agent"] = "MISP-modules/offensive-agency-lookup"
            record = fetch(session, "host/" + ip, allow_missing=True)
        objects = []
        if record is not None:
            objects = host_objects(ip, record, stable_uuid(attribute_uuid, "offensive.agency"))
            reference(objects[0], attribute_uuid, "describes")
        return {
            "results": {"Attribute": [attribute], "Object": [json.loads(obj.to_json(strict=True)) for obj in objects]}
        }
    except requests.RequestException:
        return {"error": "Offensive Agency request failed or timed out"}
    except (AttributeError, KeyError, TypeError, ValueError, PyMISPError) as exc:
        return {"error": f"Invalid Offensive Agency response: {exc}"}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": []}
