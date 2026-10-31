import csv
import json
import math
import shutil
import subprocess
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": [
        "target-user",
        "github-username",
        "text",
        "email",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
    ],
    "format": "misp_standard",
}
moduleconfig = ["sherlock_path", "sites", "timeout", "scan_timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "description": "Find social media accounts by username with Sherlock.",
    "module-type": ["expansion", "hover"],
    "name": "Sherlock Lookup",
    "logo": "",
    "requirements": [
        "Install the sherlock-project CLI separately (for example: pipx install sherlock-project). No API key required."
    ],
    "features": (
        "Runs the Sherlock CLI and returns user-account objects for claimed usernames only. Text is searched as"
        " a single literal username, without extracting names or generating variants. Email input uses the local"
        " part before @ as a candidate username; matches do not verify email ownership or identity. Install Sherlock"
        " for the misp-modules service user and put sherlock on its PATH, or set sherlock_path to the executable's"
        " absolute path (not a shell command). Optional sites is a comma-separated list of Sherlock site names;"
        " github-username defaults to GitHub only. timeout is the per-site timeout in seconds (default 10);"
        " scan_timeout bounds the whole process (default 120). Both must be positive finite numbers. Keep"
        " scan_timeout below the MISP enrichment and module-server request timeouts, or raise those timeouts"
        " for broad searches. Sherlock contacts the selected sites and downloads its current site definitions."
        " Results can contain false positives and should be reviewed."
    ),
    "references": ["https://github.com/sherlock-project/sherlock", "https://sherlockproject.xyz/usage"],
    "input": "A target-user, github-username, text, or email attribute. A leading @ on a username is removed.",
    "output": "One user-account object per match, with username, platform, profile link and a reference to the input.",
}

_EMAIL_TYPES = set(mispattributes["input"][3:])
_STATUSES = {"Claimed", "Available", "Unknown", "Illegal", "WAF"}


def _username(attribute):
    value = attribute["value"]
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A non-empty string value is required.")
    value = value.strip()
    if attribute["type"] in _EMAIL_TYPES:
        parts = value.split("@")
        if len(parts) != 2 or not all(parts) or any(char.isspace() for char in value):
            raise ValueError("A valid email address is required to derive a candidate username.")
        value = parts[0]
    elif value.startswith("@"):
        value = value[1:]
    # Sherlock names CSV reports after the username. Keep them inside the temporary directory
    # and disable Sherlock's special {?} expansion so one attribute always means one lookup.
    if (
        not value
        or len(value.encode("utf-8")) > 240
        or any(char in value for char in "/\\")
        or any(unicodedata.category(char).startswith("C") for char in value)
        or "{?}" in value
    ):
        raise ValueError("The candidate username is empty, too long, or contains unsupported characters.")
    return value


def _positive_timeout(config, name, default):
    value = config.get(name)
    if value in (None, ""):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be a positive finite number of seconds.") from None
    if isinstance(value, bool) or not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a positive finite number of seconds.")
    return number


def _read_report(report_path, username):
    matches = {}
    failures = 0
    with report_path.open(newline="", encoding="utf-8-sig") as report:
        reader = csv.DictReader(report)
        if not {"username", "name", "url_user", "exists"}.issubset(reader.fieldnames or []):
            raise ValueError("Sherlock returned an invalid CSV report.")
        for row in reader:
            if row.get("username") != username or row.get("exists") not in _STATUSES:
                raise ValueError("Sherlock returned an invalid CSV result.")
            status = row["exists"]
            if status in ("Unknown", "WAF"):
                failures += 1
            if status != "Claimed":
                continue
            site, url = row["name"], row["url_user"]
            parsed = urlsplit(url or "")
            if not site or parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError("Sherlock returned an invalid profile link.")
            matches[(site, url)] = (site, url)
    return list(matches.values()), failures


def _lookup(username, attribute_type, config):
    timeout = _positive_timeout(config, "timeout", 10)
    scan_timeout = _positive_timeout(config, "scan_timeout", 120)
    executable = config.get("sherlock_path") or "sherlock"
    if not isinstance(executable, str):
        raise ValueError("sherlock_path must be the path to the Sherlock executable.")
    executable = shutil.which(executable)
    if not executable:
        raise ValueError(
            "Sherlock is not installed or executable. Install sherlock-project or configure sherlock_path."
        )
    sites = config.get("sites") or ("GitHub" if attribute_type == "github-username" else "")
    if not isinstance(sites, str):
        raise ValueError("sites must be a comma-separated list of Sherlock site names.")
    command = [executable, "--csv", "--print-all", "--no-color", "--timeout", str(timeout)]
    for site in sites.split(","):
        if site.strip():
            command.extend(["--site", site.strip()])
    with tempfile.TemporaryDirectory(prefix="misp-sherlock-") as directory:
        command.extend(["--folderoutput", directory, "--", username])
        # Never invoke a shell. Isolate reports across requests and bound the entire scan.
        subprocess.run(
            command,
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=scan_timeout,
            check=True,
        )
        return _read_report(Path(directory) / f"{username}.csv", username)


def _parse_results(attribute, username, matches, failures):
    if not matches:
        if failures:
            return {
                "error": (
                    f"Sherlock reported no matches; {failures} site lookups failed or were blocked. Results are"
                    " incomplete."
                )
            }
        return {"error": "Sherlock reported no matching accounts on the queried sites."}
    event = MISPEvent()
    source = MISPAttribute()
    source.from_dict(**attribute)
    event.add_attribute(**source)
    comment = "Reported by Sherlock. A username match does not verify identity or email ownership."
    if failures:
        comment += f" {failures} site lookups failed or were blocked."
    for site, url in matches:
        account = MISPObject("user-account")
        account.comment = comment
        account.add_attribute("username", username, to_ids=False)
        account.add_attribute("account-type", site, to_ids=False)
        account.add_attribute("link", url, to_ids=False)
        account.add_reference(source.uuid, "related-to")
        event.add_object(account)
    result = json.loads(event.to_json())
    return {"results": {key: result[key] for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "The config field must be an object."}
    try:
        username = _username(attribute)
        matches, failures = _lookup(username, attribute["type"], config)
        return _parse_results(attribute, username, matches, failures)
    except subprocess.TimeoutExpired:
        return {"error": "Sherlock exceeded scan_timeout. Limit the sites queried or increase the timeout."}
    except subprocess.CalledProcessError as error:
        return {
            "error": f"Sherlock exited with status {error.returncode}. Check its installation and site configuration."
        }
    except (OSError, csv.Error, UnicodeError):
        return {
            "error": (
                "Unable to execute Sherlock or read its CSV report. Check the installation and service permissions."
            )
        }
    except ValueError as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
