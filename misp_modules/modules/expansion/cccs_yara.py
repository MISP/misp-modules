"""Validate YARA metadata with the Canadian Centre for Cyber Security specification."""

import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory

import yara
from yara_validator.constants import MITRE_STIX_DATA_PATH

mispattributes = {"input": ["yara"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": "Validate YARA rule metadata against the CCCS YARA specification.",
    "module-type": ["expansion", "hover"],
    "name": "CCCS YARA Metadata Validator",
    "logo": "yara.png",
    "requirements": ["cccs-yara Python library", "Local MITRE ATT&CK STIX data (MITRE_STIX_DATA_PATH)"],
    "features": (
        "Checks every rule in a YARA attribute using the upstream CCCS specification and returns errors and warnings "
        "per rule. Metadata generation is disabled and the original attribute is preserved. YARA file includes are "
        "disabled. Install the ATT&CK dataset before starting the module server; see the "
        "[setup and examples](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/cccs_yara.md)."
    ),
    "references": ["https://github.com/CybercentreCanada/CCCS-Yara"],
    "input": "A YARA attribute containing one or more rules.",
    "output": "Text describing CCCS metadata validity, errors and warnings for each rule.",
}
moduleconfig = []
logger = logging.getLogger(__name__)


def _validate(rule_content):
    # The upstream processor compiles with includes enabled. Reject them before
    # handing it any input so an attribute cannot read files on the module server.
    try:
        yara.compile(source=rule_content, includes=False)
    except yara.Error as error:
        return f"YARA syntax error (file includes are disabled): {error}"

    data_path = Path(MITRE_STIX_DATA_PATH)
    if not data_path.is_dir() or not any(
        child.is_dir() and child.name.endswith("-attack") for child in data_path.iterdir()
    ):
        raise ValueError(
            "Install the MITRE ATT&CK STIX dataset and set MITRE_STIX_DATA_PATH before starting the module server. "
            "See documentation/expansion/cccs_yara.md."
        )

    # Importing this library clones CTI when its data directory is absent.
    # Only import after checking the operator has provisioned the dataset.
    from yara_validator.validator import run_yara_validator

    with TemporaryDirectory(prefix="misp-cccs-yara-") as directory:
        rule_path = Path(directory) / "rule.yara"
        rule_path.write_text(rule_content, encoding="utf-8")
        validation = run_yara_validator(rule_path, generate_values=False)

    if validation.file_errors:
        return f"CCCS YARA validation failed:\n{validation.return_file_errors()}"
    if not validation.yara_rules:
        return "No YARA rules found."

    reports = []
    for rule in validation.yara_rules:
        invalid = not rule.rule_return.rule_validity
        state = "invalid" if invalid else "valid"
        report = [f"Rule {rule.get_rule_name()}: CCCS YARA metadata {state}."]
        if invalid:
            report.append(f"Errors:\n{rule.return_errors()}")
        if rule.return_warning():
            report.append(f"Warnings:\n{rule.return_warnings()}")
        reports.append("\n".join(report))
    return "\n\n".join(reports)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "A JSON object is required."}

    if "attribute" in request:
        attribute = request["attribute"]
        if not isinstance(attribute, dict) or attribute.get("type") != "yara":
            return {"error": "A YARA attribute is required."}
        rule_content = attribute.get("value")
    else:
        rule_content = request.get("yara")
    if not isinstance(rule_content, str) or not rule_content.strip():
        return {"error": "A non-empty YARA rule is required."}

    try:
        summary = _validate(rule_content)
    except ValueError as error:
        return {"error": str(error)}
    except Exception:
        logger.exception("CCCS YARA validation failed")
        return {"error": "CCCS YARA validation failed. Check the module server log and ATT&CK data setup."}
    return {"results": [{"types": mispattributes["output"], "values": summary}]}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
