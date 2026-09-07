import json

from . import check_input_attribute, checking_error, standard_error_message
from ._malwagon_api import DEFAULT_TIMEOUT, MalwagonClient, MalwagonError, MalwagonResults, is_sha256

mispattributes = {
    "input": ["sha256", "filename|sha256"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1",
    "author": "Tolga Sezer",
    "description": "Look up a SHA256 digest in the Malwagon sandbox and return the scans it already has for it.",
    "module-type": ["expansion", "hover"],
    "name": "Malwagon Lookup",
    "logo": "",
    "requirements": ["A Malwagon API key with the read scope."],
    "features": (
        "The module takes a sha256 or filename|sha256 attribute and asks Malwagon which analyses it already holds"
        " for that digest. The lookup is free and answers immediately, so it is safe to use on hover: no sample"
        " leaves the MISP instance and no detonation quota is spent. Only the digest is sent.\n\nEach analysis comes"
        " back as a sandbox-report object carrying the verdict, the score and a permalink to the report, referenced"
        " from a file object for the sample. The verdict is translated into MISP's own vocabulary - a"
        ' misp:threat-level tag, plus ioc:artifact-state where the verdict is conclusive - rather than being passed'
        " through as a vendor string.\n\nTo detonate something Malwagon has never seen, use the Malwagon Submit"
        " module instead."
    ),
    "references": [
        "https://malwagon.com",
        "https://malwagon.com/docs/api",
        "https://www.misp-project.org/taxonomies.html",
    ],
    "input": "A sha256 or filename|sha256 attribute.",
    "output": (
        "A file object for the sample and one sandbox-report object per Malwagon analysis, with the verdict"
        " expressed as MISP taxonomy tags."
    ),
}
# api_url exists so an operator can point the module at another deployment; it is
# not a way to send the key somewhere else silently, since the value is visible
# in the MISP server settings.
moduleconfig = ["apikey", "api_url", "max_results"]

DEFAULT_MAX_RESULTS = 10


def _digest(attribute):
    value = str(attribute.get("value", "")).strip()
    if attribute.get("type") == "filename|sha256" and "|" in value:
        value = value.split("|", 1)[1]
    return value


def _positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error} that is the digest to look up in Malwagon."}

    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    digest = _digest(attribute)
    if not is_sha256(digest):
        return {"error": "Malwagon indexes analyses by SHA256; this attribute does not carry one."}

    config = request.get("config") or {}
    if not config.get("apikey"):
        return {"error": "A Malwagon API key is required."}

    max_results = _positive_int(config.get("max_results"), DEFAULT_MAX_RESULTS)

    try:
        client = MalwagonClient(config["apikey"], config.get("api_url"), timeout=DEFAULT_TIMEOUT)
        summaries = client.lookup_hash(digest)
    except MalwagonError as error:
        return {"error": str(error)}

    if not summaries:
        return {"error": "Malwagon has no analysis for this digest."}

    results = MalwagonResults(client, sha256=digest, attribute_uuid=attribute.get("uuid"))
    for summary in summaries[:max_results]:
        results.add_scan(summary)
    return results.get_results("Malwagon returned no usable analysis for this digest.")


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
