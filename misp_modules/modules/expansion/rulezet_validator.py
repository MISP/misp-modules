import json
from datetime import datetime, timezone

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}

# MISP attribute types -> Rulezet format
ATTRIBUTE_FORMATS = {
    "yara": "yara",
    "sigma": "sigma",
    "snort": "suricata",
    "zeek": "zeek",
    "bro": "zeek",
    "kusto-query": "kql",
}

# MISP object name -> (object relation holding the rule, Rulezet format), following the
# objects Rulezet itself exports. A None format means it is read from the "format" relation.
OBJECT_FORMATS = {
    "yara": ("yara", "yara"),
    "sigma": ("sigma", "sigma"),
    "suricata": ("suricata", "suricata"),
    "zeek": ("zeek", "zeek"),
    "nse": ("nse", "nse"),
    "nse-script": ("nse", "nse"),
    "nova-rule": ("raw-rule", "nova"),
    "wazuh-rule": ("wazuh-rule", "wazuh"),
    "kunai-rule": ("kunai", "kunai"),
    "owasp-crs-rule": ("raw-rule", "crs"),
    "splunk-rule": ("spl", "splunk"),
    "elastic-detection-rule": ("query", "elastic"),
    "kql-analytics-rule": ("query", "kql"),
    "atr": ("atr", "atr"),
    "plum": ("plum", "plum"),
    "sagan": ("sagan", "sagan"),
    "rulezet-metadata": ("to-string", None),
}

mispattributes = {
    "input": list(dict.fromkeys(list(ATTRIBUTE_FORMATS) + list(OBJECT_FORMATS))),
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "Theo Geffe",
    "description": (
        "Validate the syntax of detection rules (YARA, Sigma, Suricata, Zeek, NOVA, Wazuh, Kunai, NSE, CRS,"
        " Splunk, Elastic, KQL, ATR, PLUM, Sagan) with the Rulezet API."
    ),
    "module-type": ["expansion", "hover"],
    "name": "Rulezet Rule Validator",
    "logo": "rulezet.png",
    "requirements": ["Access to a Rulezet instance (https://rulezet.org by default)"],
    "features": (
        "This module sends a rule, taken from an attribute (yara, sigma, snort, zeek, bro, kusto-query) or from an"
        " object (yara, sigma, suricata, zeek, nse, nse-script, nova-rule, wazuh-rule, kunai-rule, owasp-crs-rule,"
        " splunk-rule, elastic-detection-rule, kql-analytics-rule, atr, plum, sagan, rulezet-metadata), to the"
        " public validation endpoint of Rulezet (/api/rule/public/validate). Nothing is stored on Rulezet: it is"
        " a dry run of the syntax check Rulezet performs on rule creation.\n\n"
        "The result is returned as a `rule-validation` MISP object holding the format, the validity, and each"
        " error and warning reported by the validator, referencing the validated attribute or object."
    ),
    "references": ["https://rulezet.org", "https://github.com/rulezet/rulezet-core"],
    "input": (
        "A rule attribute (yara, sigma, snort, zeek, bro, kusto-query) or a rule object as exported by Rulezet"
        " (yara, sigma, suricata, nova-rule, wazuh-rule, owasp-crs-rule, splunk-rule, rulezet-metadata...)."
    ),
    "output": "A rule-validation MISP object.",
}
moduleconfig = ["url"]

DEFAULT_URL = "https://rulezet.org"
TIMEOUT = 30

# Not yet bundled with pymisp's misp-objects: without a template, MISP refuses the object
# (empty meta-category, no template_uuid). Must stay in sync with misp-objects.
RULE_VALIDATION_TEMPLATE = {
    "name": "rule-validation",
    "uuid": "55712239-ddd6-4235-9848-5f103ebde55b",
    "version": 1,
    "meta-category": "misc",
    "description": "Result of the syntax validation of a detection rule (YARA, Sigma, Suricata, Zeek...).",
    "required": ["format", "valid"],
    "attributes": {
        "error": {"description": "Syntax error reported by the validator", "misp-attribute": "text", "multiple": True},
        "format": {"description": "Format of the validated rule", "misp-attribute": "text"},
        "valid": {"description": "Whether the rule is syntactically valid", "misp-attribute": "boolean"},
        "validation-date": {"description": "Date of the validation", "misp-attribute": "datetime"},
        "validator": {"description": "Name of the validator used", "misp-attribute": "text"},
        "validator-url": {"description": "URL of the validator instance used", "misp-attribute": "link"},
        "warning": {"description": "Warning reported by the validator", "misp-attribute": "text", "multiple": True},
    },
}


def _extract_rule(request):
    """Return (rule content, Rulezet format, uuid of the source) or an error message."""
    attribute = request.get("attribute")
    if attribute:
        rule_format = ATTRIBUTE_FORMATS.get(attribute.get("type"))
        if rule_format is None:
            return f"Unsupported attribute type: {attribute.get('type')}"
        return attribute.get("value"), rule_format, attribute.get("uuid")

    misp_object = request.get("object")
    if misp_object:
        if misp_object.get("name") not in OBJECT_FORMATS:
            return f"Unsupported object: {misp_object.get('name')}"
        relation, rule_format = OBJECT_FORMATS[misp_object["name"]]
        values = {
            attribute.get("object_relation"): attribute.get("value")
            for attribute in misp_object.get("Attribute", [])
        }
        if not values.get(relation):
            return f"No '{relation}' attribute in the {misp_object['name']} object"
        if rule_format is None:
            rule_format = (values.get("format") or "").lower()
            if not rule_format:
                return f"No 'format' attribute in the {misp_object['name']} object"
        return values[relation], rule_format, misp_object.get("uuid")

    return "This module requires an attribute or an object as input"


def _build_object(result, base_url, source_uuid):
    validation = MISPObject("rule-validation", misp_objects_template_custom=RULE_VALIDATION_TEMPLATE)
    validation.add_attribute("format", type="text", value=result["format"])
    validation.add_attribute("valid", type="boolean", value="1" if result.get("valid") else "0")
    for error in result.get("errors", []):
        validation.add_attribute("error", type="text", value=error)
    for warning in result.get("warnings", []):
        validation.add_attribute("warning", type="text", value=warning)
    validation.add_attribute("validator", type="text", value="Rulezet")
    validation.add_attribute("validator-url", type="link", value=base_url)
    validation.add_attribute(
        "validation-date", type="datetime", value=datetime.now(timezone.utc).isoformat()
    )
    if source_uuid:
        validation.add_reference(source_uuid, "validates")
    return validation


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    extracted = _extract_rule(request)
    if isinstance(extracted, str):
        return {"error": extracted}
    rule_content, rule_format, source_uuid = extracted
    if not rule_content:
        return {"error": "Rule content missing"}

    base_url = (request.get("config") or {}).get("url") or DEFAULT_URL
    base_url = base_url.rstrip("/")
    try:
        response = requests.post(
            f"{base_url}/api/rule/public/validate",
            json={"format": rule_format, "content": rule_content},
            timeout=TIMEOUT,
        )
        result = response.json()
    except requests.RequestException as e:
        return {"error": f"Unable to reach Rulezet: {e}"}
    except ValueError:
        return {"error": f"Invalid response from Rulezet (HTTP {response.status_code})"}
    if "error" in result:
        return {"error": f"Rulezet: {result['error']}"}

    event = MISPEvent()
    event.add_object(_build_object(result, base_url, source_uuid))
    event = json.loads(event.to_json())
    return {"results": {"Object": event["Object"]}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
