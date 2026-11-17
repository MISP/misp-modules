"""Submit a URL to Internet Archive Save Page Now, without querying existing captures."""

import json
import re
import time
from datetime import datetime, timezone
from importlib import resources
from urllib.parse import urlsplit
from uuid import UUID

import requests
from pymisp import MISPObject

mispattributes = {"input": ["url", "link"], "format": "misp_standard"}
moduleconfig = ["access_key", "secret_key", "timeout", "poll_attempts"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Webarchive Save Page Now",
    "description": "Submit the supplied URL to Internet Archive Save Page Now for archiving.",
    "module-type": ["expansion"],
    "requirements": ["requests", "pymisp", "Internet Archive S3 access and secret keys"],
    "references": [
        "https://archive.org/account/s3.php",
        "https://github.com/internetarchive/openlibrary/blob/master/openlibrary/core/ia.py",
    ],
    "features": (
        "Submit one URL using POST /save. Return an archive-job receipt and optionally poll the submitted job."
        " Completed jobs produce a page-capture object; pending jobs retain their job ID and status link."
        " Does not query existing archives or retry submissions. Invoking this module discloses the URL to"
        " Internet Archive for public archiving. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/webarchive_save.md."
    ),
    "input": "A url or link attribute containing an HTTP(S) URL, with type, value and uuid.",
    "output": "An annotation with job receipt/status, plus a page-capture object for API-reported completed captures.",
}
BASE = "https://web.archive.org"
MAX_RESPONSE = 1024 * 1024


def integer(config, key, default, minimum, maximum):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)) or not minimum <= int(value) <= maximum:
        raise ValueError(f"{key} must be an integer between {minimum} and {maximum}.")
    return int(value)


def target_url(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
        or "\\" in value
    ):
        raise ValueError("Expected an HTTP(S) URL of at most 8192 characters without whitespace or backslashes.")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Expected an HTTP(S) URL with a hostname and no embedded credentials.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid URL port.")
    return parsed._replace(fragment="").geturl()


def request_json(session, method, path, timeout, data=None):
    try:
        with session.request(
            method, BASE + path, data=data, timeout=timeout, allow_redirects=False, stream=True
        ) as response:
            if response.status_code not in (200, 202):
                raise ValueError(f"Save Page Now returned HTTP {response.status_code}.")
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > MAX_RESPONSE:
                    raise ValueError("Save Page Now response exceeds 1 MiB.")
            payload = json.loads(content)
    except requests.RequestException as error:
        raise ValueError("Save Page Now request failed or timed out.") from error
    if not isinstance(payload, dict):
        raise ValueError("Save Page Now returned an invalid JSON object.")
    return payload


def capture_object(source, url, payload):
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{14}", timestamp):
        raise ValueError("Completed job is missing a valid capture timestamp.")
    captured = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    original = target_url(payload.get("original_url", url))
    template = json.loads(resources.files("misp_modules").joinpath("data/page-capture/definition.json").read_text())
    obj = MISPObject("page-capture", strict=True, standalone=False, misp_objects_template_custom=template)
    obj.add_attribute("url", value=original, to_ids=False)
    obj.add_attribute("archive", value=f"{BASE}/web/{timestamp}/{original}", to_ids=False)
    obj.add_attribute("capture-date", value=captured, to_ids=False)
    obj.comment = "Save Page Now reports this job as successful; snapshot playback was not independently checked."
    obj.add_reference(source["uuid"], "related-to")
    return obj


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected a JSON object.")
        source = request.get("attribute")
        if not isinstance(source, dict) or source.get("type") not in mispattributes["input"]:
            raise ValueError("Expected a url or link attribute with value and uuid.")
        UUID(source.get("uuid", ""))
        url = target_url(source.get("value"))
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        timeout = integer(config, "timeout", 30, 1, 120)
        attempts = integer(config, "poll_attempts", 0, 0, 6)
        keys = [config.get(name) for name in ("access_key", "secret_key")]
        if not all(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_./+=-]{1,256}", key) for key in keys):
            raise ValueError("Configure valid Internet Archive S3 access_key and secret_key.")
        receipt = {
            "provider": "Internet Archive Save Page Now",
            "url": url,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }
        objects = []
        with requests.Session() as session:
            session.headers.update(
                {
                    "Authorization": f"LOW {keys[0]}:{keys[1]}",
                    "Accept": "application/json",
                    "User-Agent": "MISP-modules/webarchive_save",
                }
            )
            try:
                payload = request_json(session, "POST", "/save", timeout, {"url": url})
            except ValueError as error:
                return {"error": f"{error} Submission outcome is unconfirmed; do not automatically resubmit."}
            identifier = payload.get("job_id")
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
                return {
                    "error": (
                        "Save Page Now did not return a valid job ID. Submission was not confirmed; do not"
                        " automatically resubmit."
                    )
                }
            path = f"/save/status/{identifier}"
            receipt.update(job_id=identifier, status="submitted", status_url=BASE + path)
            for index in range(attempts):
                if index:
                    time.sleep(2)
                try:
                    status = request_json(session, "GET", path, timeout)
                    if status.get("job_id", identifier) != identifier:
                        raise ValueError("Status response has a different job ID.")
                    state = status.get("status")
                    if state not in ("pending", "success", "error"):
                        raise ValueError("Save Page Now returned an unknown job status.")
                    if state == "success":
                        objects.append(capture_object(source, url, status))
                    receipt["status"] = state
                    if state in ("success", "error"):
                        if state == "error":
                            receipt["message"] = "Internet Archive reports that the archive job failed."
                        break
                except ValueError as error:
                    receipt["poll_error"] = (
                        str(error)
                        if not isinstance(error, json.JSONDecodeError)
                        else "Status response was not valid JSON."
                    )
                    break
        annotation = MISPObject("annotation", standalone=False)
        annotation.add_attribute(
            "text", value=json.dumps(receipt, sort_keys=True), to_ids=False, disable_correlation=True
        )
        annotation.add_reference(source["uuid"], "related-to")
        objects.insert(0, annotation)
        return {"results": {"Attribute": [source], "Object": [json.loads(obj.to_json()) for obj in objects]}}
    except (ValueError, TypeError, AttributeError) as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
