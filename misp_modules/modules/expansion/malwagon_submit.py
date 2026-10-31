import base64
import binascii
import hashlib
import io
import json
import re
import time
import zipfile

from ._malwagon_api import DEFAULT_TIMEOUT, MalwagonClient, MalwagonError, MalwagonResults, is_finished

mispattributes = {
    "input": ["attachment", "malware-sample", "url"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1",
    "author": "Tolga Sezer",
    "description": "Detonate a sample or a URL in the Malwagon sandbox and return the analysis.",
    "module-type": ["expansion"],
    "name": "Malwagon Submit",
    "logo": "",
    "requirements": ["A Malwagon API key with the submit scope."],
    "features": (
        "The module takes an attachment, malware-sample or url attribute and detonates it in the Malwagon sandbox."
        " A malware-sample arrives zip-encrypted with the password infected and is unpacked before"
        " submission.\n\nA file is looked up by its SHA256 first. If Malwagon has already analysed that digest the"
        " existing analysis is returned, which is free, instant, and spends no detonation quota; set always_submit"
        " to force a fresh detonation instead. The module then polls the scan until it finishes or until"
        " poll_timeout seconds have passed, and returns what it has either way, so a long detonation gives back a"
        " permalink rather than an error.\n\nThis module submits the sample itself to a third party, so it is"
        " deliberately expansion-only and never runs on hover. Submission is blocked when the attribute carries a"
        " TLP tag more restrictive than max_tlp, and scans are created private unless private is set to"
        " false.\n\nThe sandbox image is chosen by the platform from the sample; on the free and community tiers the"
        " analysis virtual machine has no internet access at all, which is structural rather than a quota, so"
        " network-dependent samples will look inert there."
    ),
    "references": [
        "https://malwagon.com",
        "https://malwagon.com/docs/api",
        "https://www.misp-project.org/taxonomies.html",
    ],
    "input": "An attachment, malware-sample or url attribute.",
    "output": (
        "A file object for the sample and a sandbox-report object for the Malwagon analysis, with the verdict"
        " expressed as MISP taxonomy tags."
    ),
}
moduleconfig = ["apikey", "api_url", "max_tlp", "private", "internet", "poll_timeout", "always_submit"]

# The zip password MISP uses for malware-sample attributes.
MALWARE_SAMPLE_PASSWORD = b"infected"

DEFAULT_POLL_TIMEOUT = 60
POLL_INTERVAL = 5
DEFAULT_MAX_TLP = "tlp:amber"

# Ordered so that "more restrictive than" is a comparison. tlp:clear and the
# older tlp:white are the same level, as are tlp:amber and tlp:amber+strict.
TLP_LEVELS = {
    "tlp:clear": 0,
    "tlp:white": 0,
    "tlp:green": 1,
    "tlp:amber": 2,
    "tlp:amber+strict": 2,
    "tlp:red": 3,
}

# A filename goes into a multipart header. Keep it to something that cannot
# carry a separator, a newline or a path.
FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")
MAX_FILENAME_LENGTH = 128


def _safe_filename(filename):
    name = FILENAME_RE.sub("_", str(filename or "").strip())[:MAX_FILENAME_LENGTH].lstrip(".")
    return name or "sample"


def _positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _as_bool(value, default=None):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalised = str(value).strip().lower()
    if normalised in ("true", "1", "yes", "on"):
        return True
    if normalised in ("false", "0", "no", "off"):
        return False
    return default


def _tlp_blocked(request, config):
    """Whether the classification of the input forbids sending it to a third party.

    Only the tags MISP actually passes along with the request can be inspected;
    when it passes none, this cannot fire. It is a guard against an analyst
    expanding a red-marked attribute by reflex, not a substitute for deciding
    whether the module should be enabled at all.
    """
    max_tlp = str(config.get("max_tlp") or DEFAULT_MAX_TLP).strip().lower()
    ceiling = TLP_LEVELS.get(max_tlp, TLP_LEVELS[DEFAULT_MAX_TLP])
    attribute = request.get("attribute")
    tags = attribute.get("Tag") or [] if isinstance(attribute, dict) else []
    for tag in tags:
        name = tag.get("name") if isinstance(tag, dict) else tag
        level = TLP_LEVELS.get(str(name or "").strip().lower())
        if level is not None and level > ceiling:
            return str(name).strip().lower()
    return None


def _decode_sample(data, is_malware_sample):
    """Return the raw bytes of the submitted file.

    Errors raised here are fixed strings on purpose: this function is the only
    place that holds decoded sample bytes, and a message that echoed them would
    put sample content into the MISP interface and into the module log.
    """
    if isinstance(data, bytes):
        content = data
    else:
        try:
            content = base64.b64decode(str(data), validate=True)
        except (binascii.Error, ValueError):
            raise MalwagonError("The attribute data is not valid base64.")
    if not is_malware_sample:
        return content
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
            if not names:
                raise MalwagonError("The malware-sample archive is empty.")
            return archive.read(names[0], pwd=MALWARE_SAMPLE_PASSWORD)
    except MalwagonError:
        raise
    except Exception:
        raise MalwagonError("The malware-sample attribute could not be unpacked.")


def _file_options(config):
    return {
        # Private by default: a sample pulled out of a MISP event is somebody
        # else's material, and the opt-out is explicit.
        "private": "true" if _as_bool(config.get("private"), True) else "false",
        "internet": _internet_option(config),
    }


def _internet_option(config):
    internet = _as_bool(config.get("internet"))
    if internet is None:
        return None
    return "true" if internet else "false"


def _poll(client, summary, poll_timeout):
    """Poll the scan until it is finished or the budget runs out."""
    scan_id = summary.get("scan_id")
    deadline = time.monotonic() + poll_timeout
    while not is_finished(summary) and time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            updated = client.scan_status(scan_id)
        except MalwagonError:
            # A throttled or unreachable status call is not a reason to throw
            # away the submission; return what the submit already gave us.
            break
        if updated:
            summary = updated
    return summary


def _submitted_file(request):
    if "attachment" in request:
        return _safe_filename(request.get("attachment")), _decode_sample(request.get("data"), False)
    filename = str(request.get("malware-sample") or "").split("|")[0]
    return _safe_filename(filename), _decode_sample(request.get("data"), True)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    config = request.get("config") or {}
    if not config.get("apikey"):
        return {"error": "A Malwagon API key is required."}

    if not any(key in request for key in mispattributes["input"]):
        return {"error": "No valid attribute type for this module has been provided."}

    blocked_by = _tlp_blocked(request, config)
    if blocked_by:
        return {"error": f"This attribute is marked {blocked_by}, which is above the configured max_tlp."}

    poll_timeout = _positive_int(config.get("poll_timeout"), DEFAULT_POLL_TIMEOUT)
    always_submit = _as_bool(config.get("always_submit"), False)

    try:
        client = MalwagonClient(config["apikey"], config.get("api_url"), timeout=DEFAULT_TIMEOUT)
        if "url" in request:
            sha256 = None
            summary = client.submit_target(
                "url",
                str(request["url"]),
                {"private": _as_bool(config.get("private"), True)},
            )
        else:
            filename, content = _submitted_file(request)
            sha256 = hashlib.sha256(content).hexdigest()
            summary = None
            if not always_submit:
                # Free and instant where a detonation costs minutes and a quota.
                known = client.lookup_hash(sha256)
                if known:
                    summary = known[0]
            if summary is None:
                summary = client.submit_file(filename, content, _file_options(config))
        if not summary.get("scan_id"):
            return {"error": "Malwagon accepted the submission but returned no scan identifier."}
        summary = _poll(client, summary, poll_timeout)
    except MalwagonError as error:
        return {"error": str(error)}

    results = MalwagonResults(client, sha256=sha256, attribute_uuid=request.get("attribute_uuid"))
    results.add_scan(summary)
    return results.get_results("Malwagon returned no usable analysis for this submission.")


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
