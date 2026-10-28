"""Submit mobile packages to MobSF or retrieve an existing static analysis."""

import base64
import hashlib
import io
import json
import re
import zipfile
import zlib
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

mispattributes = {"input": ["md5", "attachment", "malware-sample"], "format": "misp_standard"}
moduleconfig = ["url", "apikey", "timeout", "max_size_mb"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "MobSF",
    "description": "Submit mobile applications to MobSF or retrieve static analysis reports by MD5.",
    "module-type": ["expansion"],
    "requirements": ["requests", "Access to a MobSF instance and its API key"],
    "references": ["https://github.com/MobSF/Mobile-Security-Framework-MobSF"],
    "features": (
        "Supports Android, iOS and Windows packages accepted by the configured MobSF instance. MD5 retrieves an"
        " existing report without starting analysis. Attachments and unpacked MISP malware samples are uploaded and"
        " scanned once. Queued scans return a receipt; expand the MD5 later to retrieve results. Uses existing"
        " sandbox-report, file, android-app and software templates. See documentation/expansion/mobsf.md."
    ),
    "input": "An MD5 attribute, attachment or malware-sample with base64 data.",
    "output": (
        "Referenced analysis and application objects, with extracted network attributes and the full JSON report."
    ),
}
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ModuleError(ValueError):
    """An actionable error safe to return to the caller."""


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{%d}" % HASH_LENGTHS[kind], value):
        raise ModuleError(f"Invalid {kind} hash in request or MobSF response.")
    return value.lower()


def _integer(config, name, default, maximum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= maximum:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    return int(value)


def _settings(config):
    if not isinstance(config, dict):
        raise ModuleError("config must be a JSON object.")
    base = config.get("url")
    if not isinstance(base, str) or not base.strip():
        raise ModuleError("Configure url with the MobSF instance base URL.")
    base = base.strip().rstrip("/")
    parsed = urlsplit(base)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port == 0
        or "\\" in base
        or any(c.isspace() or ord(c) < 32 for c in base)
    ):
        raise ModuleError("url must be an HTTP(S) base URL without credentials, query or fragment.")
    key = config.get("apikey")
    if not isinstance(key, str) or not key.strip() or any(ord(c) < 32 for c in key):
        raise ModuleError("Configure apikey with a nonempty, single-line MobSF API key.")
    return base, {"Authorization": key.strip()}, _integer(config, "timeout", 120, 3600)


def _post(base, headers, timeout, endpoint, **kwargs):
    try:
        with requests.post(
            base + "/api/v1/" + endpoint,
            headers=headers,
            timeout=timeout,
            verify=True,
            allow_redirects=False,
            **kwargs,
        ) as response:
            if response.status_code == 404 and endpoint == "report_json":
                raise ModuleError("No completed MobSF report found for this MD5; analysis may still be running.")
            if not 200 <= response.status_code < 300:
                raise ModuleError(f"MobSF {endpoint} returned HTTP {response.status_code}.")
            try:
                result = response.json()
            except ValueError:
                raise ModuleError("MobSF returned invalid JSON.") from None
    except requests.Timeout:
        raise ModuleError("MobSF timed out; check the instance before submitting again.") from None
    except requests.RequestException:
        raise ModuleError("Unable to reach MobSF; check the instance URL, API key and connectivity.") from None
    if not isinstance(result, dict) or not result or "error" in result:
        raise ModuleError(f"MobSF {endpoint} returned an error or unexpected response.")
    return result


def _sample(attribute, maximum):
    name = attribute["value"]
    if attribute["type"] == "malware-sample":
        try:
            name, expected = name.rsplit("|", 1)
        except ValueError:
            raise ModuleError("malware-sample must contain filename|md5.") from None
        expected = _hash("md5", expected)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if not name.strip() or any(ord(c) < 32 for c in name):
        raise ModuleError("Invalid sample filename.")
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((maximum + 2) // 3):
        raise ModuleError("Base64 sample data within max_size_mb is required.")
    try:
        content = base64.b64decode(encoded, validate=True)
        if attribute["type"] == "malware-sample":
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = [
                    item
                    for item in archive.infolist()
                    if not item.is_dir() and not item.filename.endswith(".filename.txt")
                ]
                if len(members) != 1 or members[0].file_size > maximum:
                    raise ModuleError("The malware-sample archive must contain one sample within max_size_mb.")
                with archive.open(members[0], pwd=b"infected") as sample:
                    content = sample.read(maximum + 1)
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error, NotImplementedError):
        raise ModuleError("Unable to decode or unpack the sample within max_size_mb.") from None
    if not content or len(content) > maximum:
        raise ModuleError("The sample is empty or exceeds max_size_mb.")
    if attribute["type"] == "malware-sample" and hashlib.md5(content).hexdigest() != expected:
        raise ModuleError("The malware-sample MD5 does not match the unpacked file.")
    return name, content


def _object(event, source, name, values):
    obj = MISPObject(name, strict=True)
    for relation, value in values.items():
        if value is not None and value != "":
            obj.add_attribute(relation, value=value, to_ids=False)
    obj.add_reference(source, "related-to")
    event.add_object(obj)
    return obj


def _report(event, attribute, report, digest, base, pending=False):
    if not pending and _hash("md5", report.get("md5")) != digest:
        raise ModuleError("MobSF returned a report for a different MD5.")
    hashes = {kind: _hash(kind, report[kind]) for kind in HASH_LENGTHS if report.get(kind)}
    hashes["md5"] = digest
    source = attribute["uuid"]
    sandbox = _object(
        event,
        source,
        "sandbox-report",
        {
            "sandbox-type": "on-premise",
            "on-premise-sandbox": "MobSF",
            "raw-report": json.dumps(report, sort_keys=True),
            "permalink": base + "/search?query=" + digest,
        },
    )
    # The search URL selects the correct Android, iOS or Windows report view.
    sandbox.get_attributes_by_relation("raw-report")[0].disable_correlation = True
    file = _object(event, source, "file", {**hashes, "filename": report.get("file_name")})
    sandbox.add_reference(file.uuid, "analyzes")
    if pending:
        sandbox.comment = "Analysis queued or already scheduled; expand the MD5 later for the completed report."
        return
    if report.get("package_name") and not report.get("bundle_id"):
        app = _object(
            event,
            source,
            "android-app",
            {
                "appid": report["package_name"],
                "name": report.get("app_name"),
                "sha256": hashes.get("sha256"),
            },
        )
        file.add_reference(app.uuid, "contains")
    elif report.get("app_name") or report.get("bundle_id"):
        app = _object(
            event,
            source,
            "software",
            {
                "name": report.get("app_name") or report["bundle_id"],
                "version": report.get("app_version") or report.get("version_name"),
            },
        )
        file.add_reference(app.uuid, "contains")
    indicators = set()
    domains = report.get("domains") or {}
    if not isinstance(domains, dict):
        raise ModuleError("MobSF returned an unexpected domains collection.")
    for domain in domains:
        if isinstance(domain, str) and domain.strip():
            indicators.add(("domain", domain))
    for field, kind, key in (("urls", "url", "urls"), ("emails", "email-dst", "emails")):
        rows = report.get(field) or []
        if not isinstance(rows, list):
            raise ModuleError(f"MobSF returned an unexpected {field} collection.")
        for row in rows:
            entries = row.get(key, []) if isinstance(row, dict) else [row]
            if isinstance(entries, str):
                entries = [entries]
            if not isinstance(entries, list):
                raise ModuleError(f"MobSF returned an unexpected {field} entry.")
            for value in entries:
                if isinstance(value, str) and value.strip():
                    indicators.add((kind, value))
    for kind, value in sorted(indicators):
        indicator = event.add_attribute(kind, value, to_ids=False, comment="Extracted by MobSF static analysis.")
        sandbox.add_reference(indicator.uuid, "contains")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(k) for k in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type; use md5, attachment or malware-sample.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty string.")
        config = request.get("config", {})
        base, headers, timeout = _settings(config)
        maximum = _integer(config, "max_size_mb", 50, 500) * 1024 * 1024
        event = MISPEvent()
        # Preserve the original container without PyMISP decoding ZIP metadata before our size checks.
        event.add_attribute(**{key: value for key, value in attribute.items() if key != "data"})
        pending = False
        if attribute["type"] == "md5":
            digest = _hash("md5", attribute["value"].strip())
            report = _post(base, headers, timeout, "report_json", data={"hash": digest})
        else:
            filename, content = _sample(attribute, maximum)
            digest = hashlib.md5(content).hexdigest()
            upload = _post(base, headers, timeout, "upload", files={"file": (filename, content)})
            if _hash("md5", upload.get("hash")) != digest:
                raise ModuleError("MobSF upload returned a different file hash; analysis was not started.")
            report = _post(base, headers, timeout, "scan", data={"hash": digest})
            pending = "task_id" in report
            if pending:
                report = {**report, "md5": digest, "file_name": filename}
        _report(event, attribute, report, digest, base, pending)
        data = json.loads(event.to_json())
        if "data" in attribute:
            data["Attribute"][0]["data"] = attribute["data"]
        return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as error:
        return {"error": str(error)}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, PyMISPError):
        return {"error": "Invalid request or MobSF response."}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
