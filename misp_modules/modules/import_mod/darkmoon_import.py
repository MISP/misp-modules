import base64
import json

from pymisp import MISPObject

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.1",
    "author": "ASC-IT",
    "description": "Module to import the JSON findings of the Darkmoon autonomous AI penetration testing platform.",
    "module-type": ["import"],
    "name": "Darkmoon Import",
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Takes the JSON findings file written by the Darkmoon open source CLI (either a list of findings or an object"
        " with a `findings` list) and creates one `vulnerability` object per finding, with the CVE, the CVSS score and"
        " vector, the description, the remediation and the evidence that proves it. The endpoint of the finding is"
        " added as a `url` object that the vulnerability affects. The severity, the exploitation status (exploited,"
        " confirmed or unconfirmed) and the MITRE ATT&CK technique are added as tags."
    ),
    "references": ["https://github.com/ASCIT31/Dark-Moon"],
    "input": "Darkmoon JSON findings file",
    "output": "MISP vulnerability and url objects",
}

moduleconfig = []

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}

userConfig = {
    "include_unconfirmed": {
        "type": "Boolean",
        "message": "Include findings whose exploitation could not be confirmed",
        "checked": "true",
    },
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
EXPLOITATION_STATUSES = {
    "exploited": "proven with a working exploit",
    "confirmed": "confirmed",
    "unconfirmed": "not confirmed",
}


def _is_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def get_findings(data):
    """Return the list of findings of a Darkmoon report, or None when the data is not a Darkmoon report."""
    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list) or not data:
        return None
    for finding in data:
        # `discovered_by_agent` and the exploitation `status` are specific to Darkmoon
        if not (
            isinstance(finding, dict)
            and finding.get("title")
            and finding.get("discovered_by_agent")
            and str(finding.get("status", "")).lower() in EXPLOITATION_STATUSES
        ):
            return None
    return data


def _description(finding):
    parts = [str(finding.get("description") or "").strip()]
    if finding.get("remediation"):
        parts.append("Remediation: {}".format(str(finding["remediation"]).strip()))
    if finding.get("evidence_explanation"):
        parts.append("Evidence: {}".format(str(finding["evidence_explanation"]).strip()))
    commands = finding.get("evidence_commands")
    if isinstance(commands, list) and commands:
        parts.append("Commands:\n{}".format("\n".join(str(command) for command in commands)))
    elif commands:
        parts.append("Commands:\n{}".format(commands))
    if finding.get("evidence_logs"):
        parts.append("Logs:\n{}".format(finding["evidence_logs"]))
    if finding.get("raw_request"):
        parts.append("Request:\n{}".format(finding["raw_request"]))
    if finding.get("raw_response"):
        parts.append("Response:\n{}".format(finding["raw_response"]))
    return "\n\n".join(part for part in parts if part)


def _tags(finding, status):
    tags = ["darkmoon:exploitation-status={}".format(json.dumps(status))]
    severity = str(finding.get("severity") or "").lower()
    if severity in SEVERITIES:
        tags.append("darkmoon:severity={}".format(json.dumps(severity)))
    if finding.get("category"):
        tags.append("darkmoon:category={}".format(json.dumps(str(finding["category"]))))
    if finding.get("discovered_by_agent"):
        tags.append("darkmoon:agent={}".format(json.dumps(str(finding["discovered_by_agent"]))))
    technique = finding.get("mitre_attack_id")
    if technique and finding.get("mitre_attack_name"):
        tags.append(
            "misp-galaxy:mitre-attack-pattern={}".format(
                json.dumps("{} - {}".format(finding["mitre_attack_name"], technique))
            )
        )
    return [{"name": tag} for tag in tags]


def _references(finding):
    references = []
    if finding.get("cve"):
        references.append("https://nvd.nist.gov/vuln/detail/{}".format(finding["cve"]))
    technique = finding.get("mitre_attack_id")
    if technique:
        references.append("https://attack.mitre.org/techniques/{}/".format(str(technique).replace(".", "/")))
    return references


def parse_finding(finding):
    """Convert one Darkmoon finding to a vulnerability object and, with an endpoint, the url object it affects."""
    status = str(finding.get("status")).lower()
    vulnerability = MISPObject("vulnerability", standalone=False, comment="created by darkmoon_import")
    vulnerability.add_attribute("summary", value=str(finding["title"]), Tag=_tags(finding, status))
    vulnerability.add_attribute("description", value=_description(finding))
    if finding.get("cve"):
        vulnerability.add_attribute("id", value=str(finding["cve"]))
    if finding.get("cvss_score") is not None:
        vulnerability.add_attribute("cvss-score", value=str(finding["cvss_score"]))
    if finding.get("cvss_vector"):
        vulnerability.add_attribute("cvss-string", value=str(finding["cvss_vector"]))
    for reference in _references(finding):
        vulnerability.add_attribute("references", value=reference)

    objects = [vulnerability]
    if finding.get("endpoint"):
        url = MISPObject("url", standalone=False, comment="endpoint of the Darkmoon finding")
        url.add_attribute("url", value=str(finding["endpoint"]))
        vulnerability.add_reference(url.uuid, "affects")
        objects.append(url)
    return objects


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    try:
        report = json.loads(base64.b64decode(request["data"]).decode("utf-8"))
    except (KeyError, ValueError):
        misperrors["error"] = "The input is not a valid JSON file."
        return misperrors
    findings = get_findings(report)
    if findings is None:
        misperrors["error"] = "The input is not a Darkmoon JSON findings report."
        return misperrors

    config = request.get("config") or {}
    include_unconfirmed = _is_enabled(config.get("include_unconfirmed"))

    objects = []
    for finding in findings:
        if not include_unconfirmed and str(finding.get("status")).lower() == "unconfirmed":
            continue
        objects.extend(parse_finding(finding))
    return {"results": {"Object": [json.loads(misp_object.to_json()) for misp_object in objects]}}


def introspection():
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
