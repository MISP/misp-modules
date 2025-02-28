import json

import requests

from . import check_input_attribute, standard_error_message
from ._vulnerability_parser.vulnerability_parser import VulnerabilityLookupParser

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "format": "misp_standard"}
moduleinfo = {
    "version": "2",
    "author": "Alexandre Dulaunoy",
    "description": "An expansion hover module to expand information about CVE id.",
    "module-type": ["expansion", "hover"],
    "name": "CVE Lookup",
    "logo": "vulnerability_lookyp.png",
    "requirements": [],
    "features": (
        "The module takes a vulnerability attribute as input and queries Vulnerability Lookup to get additional"
        " information based on the Vulnerability ID."
    ),
    "references": ["https://cve.circl.lu/", "https://cve.mitre.org/"],
    "input": "Vulnerability attribute.",
    "output": "Additional information on the vulnerability, gathered from the Vulnerability Lookup API.",
}
api_url = "https://cve.circl.lu"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not check_input_attribute(request.get("attribute", {})):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an UUID."}
    attribute = request["attribute"]
    if attribute.get("type") != "vulnerability":
        return {"error": 'The attribute type should be "vulnerability".'}
    lookup = requests.get(f"{api_url}/api/vulnerability/{attribute['value']}")
    if lookup.status_code == 200:
        vulnerability = lookup.json()
        if not vulnerability:
            return {"error": "Non existing vulnerability ID."}
    else:
        return {"error": "Vulnerability Lookup API not accessible."}
    parser = VulnerabilityLookupParser(attribute, api_url)
    parser.parse_lookup_result(vulnerability)
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    return moduleinfo
