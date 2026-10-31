"""Submit MISP files to Pandora and return a shareable analysis link."""

import base64
import io
import json
import zipfile
import zlib
from urllib.parse import quote, urlsplit

import requests

DEFAULT_URL = "https://pandora.circl.lu"
mispattributes = {"input": ["attachment", "malware-sample"], "output": ["link"]}
moduleconfig = ["url", "apikey", "timeout", "validity", "password"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Pandora Submit",
    "description": "Submit attachments and malware samples to Pandora and return a link to the analysis.",
    "module-type": ["expansion"],
    "requirements": ["requests", "Access to a Pandora instance; API key optional"],
    "references": ["https://github.com/pandora-analysis/pandora", DEFAULT_URL],
    "features": (
        "Submits files to https://pandora.circl.lu by default. Set url to use another Pandora instance, including a"
        " deployment under a path prefix. apikey is optional. timeout defaults to 30 seconds. validity controls the"
        " shareable report link lifetime in seconds (default 0: no expiry). password optionally decrypts archives in"
        " Pandora. MISP malware-sample ZIPs are unpacked locally with the standard infected password. Submission starts"
        " an analysis; the module returns immediately without polling. See documentation/expansion/pandora_submit.md."
    ),
    "input": "An attachment or a malware-sample with base64-encoded data.",
    "output": "A link to the Pandora analysis, including its access seed.",
}


class ModuleError(ValueError):
    """An error safe to return to the caller."""


def _base_url(value):
    if value is None or value == "":
        return DEFAULT_URL
    if not isinstance(value, str):
        raise ModuleError("url must be an HTTP(S) Pandora instance URL.")
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ModuleError("Invalid Pandora instance URL.") from None
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
        or "\\" in value
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ModuleError("url must be an HTTP(S) instance URL without credentials, query or fragment.")
    return value


def _integer(config, name, default, minimum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ModuleError(f"{name} must be an integer of at least {minimum}.")
    try:
        number = int(value)
    except ValueError:
        raise ModuleError(f"{name} must be an integer of at least {minimum}.") from None
    if number < minimum:
        raise ModuleError(f"{name} must be an integer of at least {minimum}.")
    return number


def _sample(request):
    kinds = [kind for kind in mispattributes["input"] if kind in request]
    if len(kinds) != 1:
        raise ModuleError("Supply exactly one attachment or malware-sample.")
    kind = kinds[0]
    filename = request[kind]
    if not isinstance(filename, str) or not filename.strip():
        raise ModuleError("A sample filename is required.")
    if kind == "malware-sample":
        filename = filename.rsplit("|", 1)[0]
    if not filename.strip():
        raise ModuleError("A sample filename is required.")
    encoded = request.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise ModuleError("Base64-encoded sample data is required.")
    try:
        data = base64.b64decode(encoded, validate=True)
        if kind == "malware-sample":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = [
                    item
                    for item in archive.infolist()
                    if not item.is_dir() and not item.filename.endswith(".filename.txt")
                ]
                if len(members) != 1:
                    raise ModuleError("A malware-sample archive must contain exactly one sample.")
                data = archive.read(members[0], pwd=b"infected")
    except ModuleError:
        raise
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error):
        raise ModuleError("Unable to decode or unpack the sample data.") from None
    if not data.strip():
        raise ModuleError("Pandora cannot analyze an empty file.")
    return filename, data


def handler(q=False):
    if q is False:
        return False
    try:
        try:
            request = json.loads(q)
        except (ValueError, TypeError):
            raise ModuleError("Invalid JSON request.") from None
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        config = request.get("config", {})
        if not isinstance(config, dict):
            raise ModuleError("config must be a JSON object.")
        base = _base_url(config.get("url"))
        timeout = _integer(config, "timeout", 30, 1)
        validity = _integer(config, "validity", 0, 0)
        api_key = config.get("apikey") or ""
        password = config.get("password") or ""
        if not isinstance(api_key, str) or "\r" in api_key or "\n" in api_key:
            raise ModuleError("apikey must be a single-line string.")
        if not isinstance(password, str):
            raise ModuleError("password must be a string.")
        filename, data = _sample(request)
        headers = {"Authorization": api_key.strip()} if api_key.strip() else {}
        params = {"validity": validity}
        if password:
            params["password"] = password
        # Match PyPandora: validity and password are query parameters.
        # Do not retry or follow redirects: a submission starts a new analysis.
        try:
            with requests.post(
                base + "/submit",
                files={"file": (filename, data)},
                params=params,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            ) as response:
                if response.status_code in (401, 403):
                    raise ModuleError("Pandora denied submission; check the API key and instance permissions.")
                if not 200 <= response.status_code < 300:
                    raise ModuleError(f"Pandora submission failed (HTTP {response.status_code}).")
                try:
                    result = response.json()
                except ValueError:
                    raise ModuleError("Pandora returned an invalid JSON response.") from None
        except requests.exceptions.Timeout:
            raise ModuleError("Pandora submission timed out; check the instance before submitting again.") from None
        except requests.exceptions.RequestException:
            raise ModuleError("Unable to submit to Pandora; check the instance URL and connectivity.") from None
        if not isinstance(result, dict) or result.get("success") is not True:
            raise ModuleError("Pandora did not accept the submission.")
        task_id, seed = result.get("taskId"), result.get("seed")
        if not all(isinstance(value, str) and value.strip() for value in (task_id, seed)):
            raise ModuleError("Pandora accepted the submission but did not return a task ID and access seed.")
        report = f"{base}/analysis/{quote(task_id, safe='')}/seed-{quote(seed, safe='')}"
        return {
            "results": [
                {
                    "types": "link",
                    "categories": "External analysis",
                    "values": report,
                    "comment": "Submitted to Pandora; analysis may still be running.",
                }
            ]
        }
    except ModuleError as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
