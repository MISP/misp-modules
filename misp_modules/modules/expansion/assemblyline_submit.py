# -*- coding: utf-8 -*-
import base64
import binascii
import json
from io import BytesIO
from urllib.parse import urljoin

from ._assemblyline_api import AssemblyLineAPI, AssemblyLineError

moduleinfo = {
    "version": 1,
    "author": "Christian Studer",
    "module-type": ["expansion"],
    "name": "AssemblyLine Submit",
    "description": (
        "A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the"
        " submission."
    ),
    "logo": "assemblyline.png",
    "requirements": [],
    "features": (
        "The module requires the address of the AssemblyLine server you want to query as well as your credentials used"
        " for this instance. Credentials include the user-ID and an API key or the password associated to the"
        " user-ID.\n\nIf the sample or url is correctly submitted, you get then the link of the submission."
    ),
    "references": ["https://www.cyber.gc.ca/en/assemblyline"],
    "input": "Sample, or url to submit to AssemblyLine.",
    "output": "Link of the report generated in AssemblyLine.",
}
moduleconfig = ["apiurl", "user_id", "apikey", "password", "verifyssl"]
mispattributes = {"input": ["attachment", "malware-sample", "url"], "output": ["link"]}


def _coerce_verify_flag(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"true", "1", "yes", "on"}:
            return True
        if normalised in {"false", "0", "no", "off"}:
            return False
    return default


def parse_config(apiurl, user_id, config):
    verify = _coerce_verify_flag(config.get("verifyssl"), default=True)
    api_key = config.get("apikey")
    password = config.get("password")
    errors = []
    if api_key:
        client = AssemblyLineAPI(apiurl, verify=verify)
        try:
            client.authenticate(user=user_id, apikey=api_key)
            return client
        except AssemblyLineError as e:
            errors.append(f"API key authentication failed: {e}")
    if password:
        client = AssemblyLineAPI(apiurl, verify=verify)
        try:
            client.authenticate(user=user_id, password=password)
            return client
        except AssemblyLineError as e:
            errors.append(f"Password authentication failed: {e}")
    if errors:
        return {"error": " ".join(errors)}
    return {"error": "Please provide your AssemblyLine API key or Password."}


def submit_content(client, filename, data):
    try:
        file_bytes = _decode_attribute_data(data)
        file_handle = BytesIO(file_bytes)
        file_handle.name = filename or "sample"
        file_handle.seek(0)
        request_payload = {"name": filename or "sample"}
        return client.post_multipart(
            "/api/v4/submit/",
            data={"json": json.dumps(request_payload)},
            files={"bin": (file_handle.name, file_handle)},
        )
    except AssemblyLineError as e:
        return {"error": f"Error while submitting content to AssemblyLine: {e}"}


def submit_request(client, request):
    if "attachment" in request:
        return submit_content(client, request["attachment"], request["data"])
    if "malware-sample" in request:
        return submit_content(client, request["malware-sample"].split("|")[0], request["data"])
    for feature in ("url", "domain"):
        if feature in request:
            return submit_url(client, request[feature])
    return {"error": "No valid attribute type for this module has been provided."}


def submit_url(client, url):
    try:
        payload = {"url": url, "name": url}
        return client.post_json("/api/v4/submit/", payload)
    except AssemblyLineError as e:
        return {"error": f"Error while submitting url to AssemblyLine: {e}"}


def _decode_attribute_data(data):
    if isinstance(data, str):
        try:
            return base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            return data.encode()
    return data


def handler(q=False):
    if q is False:
        return q
    request = q if isinstance(q, dict) else json.loads(q)
    if not request.get("config"):
        return {"error": "Missing configuration."}
    if not request["config"].get("apiurl"):
        return {"error": "No AssemblyLine server address provided."}
    apiurl = request["config"]["apiurl"]
    if not request["config"].get("user_id"):
        return {"error": "Please provide your AssemblyLine User ID."}
    user_id = request["config"]["user_id"]
    client = parse_config(apiurl, user_id, request["config"])
    if isinstance(client, dict):
        return client
    submission = submit_request(client, request)
    if "error" in submission:
        return submission
    sid = _extract_submission_id(submission)
    if not sid:
        return {
            "error": "Unexpected response received from AssemblyLine.",
            "response": submission,
        }
    return {
        "results": [
            {
                "types": "link",
                "categories": "External analysis",
                "values": _build_submission_url(apiurl, sid),
            }
        ]
    }


def dict_handler(request=False):
    return handler(request)


def introspection():
    return mispattributes


def _extract_submission_id(submission):
    if not isinstance(submission, dict):
        return None
    submission_section = submission.get("submission")
    if isinstance(submission_section, dict):
        for key in ("sid", "submission_id", "submissionId"):
            if submission_section.get(key):
                return submission_section[key]
    for key in ("sid", "submission_id", "submissionId", "task_id"):
        if submission.get(key):
            return submission[key]
    return None


def _build_submission_url(apiurl, sid):
    if not apiurl:
        return sid
    base = apiurl.rstrip("/") + "/"
    return urljoin(base, f"submission/detail/{sid}")


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
