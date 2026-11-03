import json
import re
from datetime import datetime, timezone
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["vulnerability", "cpe"], "format": "misp_standard"}
moduleconfig = ["apikey", "details", "limit", "timeout"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "description": "Expand CVEs, VulDB identifiers and CPEs using the VulDB API.",
    "module-type": ["expansion"],
    "data-source": "external",
    "name": "VulDB",
    "requirements": ["requests", "pymisp", "A VulDB API key"],
    "features": (
        "Look up CVEs with an exact advanced search, VulDB IDs with an ID request, or CPEs with a product search. "
        "Returns one vulnerability object per entry, linked to the original attribute. "
        "apikey is required. details defaults to false; enabling it consumes one API credit per returned entry "
        "and requires the appropriate subscription. limit defaults to 10 (1-100); timeout defaults to 30 seconds "
        "(maximum 120). Null or blank optional settings use these defaults. "
        "One request is made per enrichment, without automatic retries or pagination. "
        "CPE search is experimental in VulDB; check version applicability before using the results. "
        "See the usage guide: https://github.com/MISP/misp-modules/blob/main/documentation/expansion/vuldb.md"
    ),
    "references": ["https://vuldb.com/", "https://vuldb.com/kb/api"],
    "input": "A vulnerability attribute containing a CVE, VULDB-67685 or numeric VulDB ID; or a CPE attribute.",
    "output": (
        "Vulnerability objects with identifiers, titles, dates and references; optional descriptions, CPEs and CVSS."
    ),
}
API_URL = "https://vuldb.com/?api"
API_ERRORS = {
    "400": "VulDB rejected the request.",
    "401": "VulDB authentication failed. Check the API key.",
    "402": "The VulDB subscription does not permit this query or detail level.",
    "403": "VulDB API credits are exhausted or access is denied.",
    "405": "VulDB did not recognize the request type.",
    "409": "VulDB temporarily blocked API access due to suspected abuse.",
    "429": "VulDB rate limit reached. Try again later.",
}


def _mapping(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Invalid response section")
    return value


def _values(value):
    if value is None or value == "":
        return []
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(item, str) for item in values):
        raise ValueError("Invalid response value")
    return list(dict.fromkeys(item for item in values if item))


def _add(obj, relation, value, **kwargs):
    if value is not None and value != "":
        obj.add_attribute(relation, value=value, to_ids=False, **kwargs)


def _date(value):
    if value is None or value == "":
        return None
    # Zero is used for unknown dates, not a publication on the Unix epoch.
    timestamp = float(value)
    if timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _parse_entry(record, source_uuid):
    record = _mapping(record)
    entry = _mapping(record.get("entry"))
    identifier = str(entry.get("id", ""))
    if not re.fullmatch(r"[1-9][0-9]*", identifier):
        raise ValueError("Missing VulDB ID")
    obj = MISPObject("vulnerability")
    obj.comment = f"VulDB entry {identifier}"
    _add(obj, "id", f"VULDB-{identifier}")
    cves = _values(_mapping(_mapping(record.get("source")).get("cve")).get("id"))
    for cve in cves:
        if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve, re.IGNORECASE):
            _add(obj, "id", cve.upper())
    _add(obj, "summary", entry.get("title"))
    _add(obj, "description", entry.get("summary"))
    _add(obj, "impact", _mapping(entry.get("details")).get("impact"))
    timestamps = _mapping(entry.get("timestamp"))
    # Entry creation is a database timestamp; advisory.date is disclosure.
    _add(obj, "published", _date(_mapping(record.get("advisory")).get("date")))
    _add(obj, "modified", _date(timestamps.get("change")))
    _add(obj, "references", f"https://vuldb.com/?id.{identifier}")
    advisory_url = _mapping(record.get("advisory")).get("url")
    for url in _values(advisory_url):
        _add(obj, "references", url)
    software = _mapping(record.get("software"))
    for cpe in _values(software.get("cpe23") or software.get("cpe")):
        _add(obj, "vulnerable-configuration", cpe)
    vulnerability = _mapping(record.get("vulnerability"))
    # Select a score and its vector from the same version and producer.
    for generation in ("cvss3", "cvss2"):
        scores = _mapping(vulnerability.get(generation))
        for producer in ("vuldb", "nvd", "cna"):
            score = _mapping(scores.get(producer))
            if score.get("basescore") not in (None, ""):
                score_value = float(score["basescore"])
                if not 0 <= score_value <= 10:
                    raise ValueError("Invalid CVSS score")
                comment = f"VulDB API: {generation.upper()} base score from {producer}"
                _add(obj, "cvss-score", score_value, comment=comment)
                _add(obj, "cvss-string", score.get("basevector"), comment=comment)
                obj.add_reference(source_uuid, "related-to")
                return obj
    obj.add_reference(source_uuid, "related-to")
    return obj


def _options(config):
    config = {
        key: value
        for key, value in config.items()
        if value is not None and not (isinstance(value, str) and not value.strip())
    }
    apikey = config.get("apikey")
    if not isinstance(apikey, str) or not apikey.strip():
        raise ValueError("A VulDB API key is required.")
    details = str(config.get("details", False)).strip().lower()
    if details not in ("true", "false", "1", "0"):
        raise ValueError("details must be true or false.")
    try:
        limit = int(str(config.get("limit", 10)))
        timeout = float(config.get("timeout", 30))
        if not 1 <= limit <= 100 or not 0 < timeout <= 120:
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        raise ValueError("limit must be an integer from 1 to 100; timeout must be greater than 0 and at most 120.")
    return apikey.strip(), details in ("true", "1"), limit, timeout


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
        return {"error": standard_error_message}
    attribute = request["attribute"]
    if not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, with a type, a value and a UUID."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "A vulnerability or CPE attribute is required."}
    value = attribute["value"]
    if not isinstance(value, str) or not value.strip():
        return {"error": "An empty or non-string lookup value is not supported."}
    try:
        UUID(attribute["uuid"])
    except (ValueError, TypeError, AttributeError):
        return {"error": "The input attribute must have a valid UUID."}
    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "Invalid module configuration."}
    try:
        apikey, details, limit, timeout = _options(config)
    except ValueError as error:
        return {"error": str(error)}
    data = {"version": 3, "format": "json", "details": int(details), "limit": limit}
    value = value.strip()
    if attribute["type"] == "cpe":
        if not value.startswith(("cpe:/", "cpe:2.3:")):
            return {"error": "A CPE 2.2 or 2.3 string is required."}
        data["search"] = value
    elif re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value, re.IGNORECASE):
        data["advancedsearch"] = f"cve:{value.upper()}"
    else:
        match = re.fullmatch(r"(?:VULDB-)?([1-9][0-9]*)", value, re.IGNORECASE)
        if match is None:
            return {"error": "A CVE identifier or a numeric VulDB ID (optionally prefixed VULDB-) is required."}
        data["id"] = match[1]
    try:
        response = requests.post(
            API_URL,
            data=data,
            headers={"X-VulDB-ApiKey": apikey},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        return {"error": "The VulDB API request timed out."}
    except requests.exceptions.RequestException:
        return {"error": "Unable to contact the VulDB API."}
    if response.status_code == 204:
        return {"results": {}}
    if response.status_code != 200:
        return {"error": API_ERRORS.get(str(response.status_code), "The VulDB API returned an HTTP error.")}
    try:
        payload = _mapping(response.json())
        status = str(_mapping(payload.get("response")).get("status", ""))
        if status == "204":
            return {"results": {}}
        if status != "200":
            return {"error": API_ERRORS.get(status, "The VulDB API returned an unsuccessful or invalid response.")}
        records = payload.get("result")
        if not isinstance(records, list):
            raise ValueError("Missing result list")
        if not records:
            return {"results": {}}
        event = MISPEvent()
        original = MISPAttribute()
        original.from_dict(**attribute)
        event.add_attribute(**original)
        seen = set()
        for record in records[:limit]:
            obj = _parse_entry(record, original.uuid)
            identifier = obj.attributes[0].value
            if identifier not in seen:
                event.add_object(obj)
                seen.add(identifier)
        result = json.loads(event.to_json())
        return {"results": {key: result[key] for key in ("Attribute", "Object") if result.get(key)}}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError):
        # Never echo response bodies or transport exceptions: these can contain credentials.
        return {"error": "The VulDB API returned an invalid response or vulnerability entry."}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
