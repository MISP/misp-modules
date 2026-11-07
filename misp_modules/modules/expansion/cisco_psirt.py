"""Look up Cisco PSIRT openVuln v2 advisories by CVE, advisory or bug ID."""

import hashlib
import json
import math
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlsplit
from uuid import UUID

import requests
from bs4 import BeautifulSoup
from pymisp import MISPEvent, MISPObject

mispattributes = {"input": ["vulnerability", "text"], "format": "misp_standard"}
moduleconfig = ["client_id", "client_secret", "max_advisories", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cisco PSIRT",
    "description": "Retrieve Cisco PSIRT security advisories by CVE, Cisco advisory ID or Cisco bug ID.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "logo": "",
    "requirements": ["Cisco API Console client credentials authorized for the PSIRT openVuln API."],
    "features": (
        "Uses OAuth client credentials and the openVuln v2 API. Returns linked vulnerability and annotation objects"
        " with advisory details, CVEs, CVSS, UTC dates, product names, bug IDs, CWEs and CSAF links. Filters partial"
        " bug-ID matches. See https://github.com/MISP/misp-modules/blob/main/documentation/expansion/cisco_psirt.md."
    ),
    "references": [
        "https://developer.cisco.com/docs/psirt/introduction/",
        "https://developer.cisco.com/docs/psirt/authentication/",
        "https://developer.cisco.com/docs/psirt/obtain-advisory-by-identifiers/",
    ],
    "input": (
        "A vulnerability attribute containing a CVE, or a text attribute containing a CVE, cisco-sa-* or CSCxx12345 ID."
    ),
    "output": (
        "The original attribute, advisory vulnerability objects and referenced context annotations; new attributes are"
        " non-IDS."
    ),
}
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_URL = "https://apix.cisco.com/security/advisories/v2"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_TOKENS = OrderedDict()
_TOKEN_LOCK = Lock()


class PsirtError(ValueError):
    """A message safe to return without credentials or provider error bodies."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _Auth(requests.auth.AuthBase):
    def __init__(self, token=None):
        self.token = token

    def __call__(self, request):
        # Explicit auth prevents .netrc from overriding the selected OAuth flow.
        if self.token is not None:
            request.headers["Authorization"] = "Bearer " + self.token
        return request


def _request(session, method, url, timeout, missing=False, **kwargs):
    with session.request(method, url, timeout=timeout, allow_redirects=False, stream=True, **kwargs) as response:
        if response.status_code != 200 and not (missing and response.status_code == 404):
            raise PsirtError(f"Cisco PSIRT returned HTTP {response.status_code}.", response.status_code)
        content = bytearray()
        for chunk in response.iter_content(65536):
            content.extend(chunk)
            if len(content) > MAX_RESPONSE_BYTES:
                raise PsirtError("Cisco PSIRT response exceeds the 2 MiB limit.")
        try:
            data = json.loads(content)
        except (ValueError, RecursionError):
            raise PsirtError("Cisco PSIRT returned invalid JSON.") from None
        if not isinstance(data, dict):
            raise PsirtError("Cisco PSIRT returned an invalid response.")
        if response.status_code == 404:
            if data.get("errorCode") in ("NO_DATA_FOUND", "ADVISORYID_NOT_FOUND"):
                return None
            raise PsirtError("Cisco PSIRT returned HTTP 404 with an unexpected error code.")
        if any(field in data for field in ("error", "errors", "errorCode")):
            raise PsirtError("Cisco PSIRT reported an API error.")
        return data


def _token(session, client_id, secret, timeout):
    identity = hashlib.sha256(json.dumps([client_id, secret]).encode()).digest()
    with _TOKEN_LOCK:
        now = time.monotonic()
        for key, (_, expiry) in list(_TOKENS.items()):
            if expiry <= now:
                del _TOKENS[key]
        if identity in _TOKENS:
            _TOKENS.move_to_end(identity)
            return identity, _TOKENS[identity][0]
        data = _request(
            session,
            "POST",
            TOKEN_URL,
            timeout,
            auth=_Auth(),
            data={"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials"},
        )
        token, expires = data.get("access_token"), data.get("expires_in")
        if (
            not isinstance(token, str)
            or len(token) > 16384
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)
            or not isinstance(data.get("token_type"), str)
            or data["token_type"].lower() != "bearer"
            or type(expires) is not int
            or expires <= 0
        ):
            raise PsirtError("Cisco PSIRT returned an invalid token response.")
        lifetime = min(expires, 3600)
        _TOKENS[identity] = (token, now + lifetime - min(60, lifetime / 10))
        while len(_TOKENS) > 32:
            _TOKENS.popitem(last=False)
        return identity, token


def _identifier(value):
    if not isinstance(value, str) or len(value) > 200:
        raise PsirtError("A CVE, Cisco advisory ID or Cisco bug ID is required.")
    value = value.strip()
    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value, re.IGNORECASE):
        return "cve", value.upper()
    if re.fullmatch(r"cisco-sa-[A-Za-z0-9][A-Za-z0-9_-]*", value):
        return "advisory", value
    if re.fullmatch(r"CSC[a-z]{2}[0-9]{5}", value, re.IGNORECASE):
        return "bugid", "CSC" + value[3:5].lower() + value[5:]
    raise PsirtError("A CVE, Cisco advisory ID or Cisco bug ID is required.")


def _integer(config, name, default, maximum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,3}", str(value)) or not 1 <= int(value) <= maximum:
        raise PsirtError(f"{name} must be an integer between 1 and {maximum}.")
    return int(value)


def _settings(request):
    source, config = request.get("attribute"), request.get("config")
    if not isinstance(source, dict) or source.get("type") not in mispattributes["input"]:
        raise PsirtError("A vulnerability or text attribute with a UUID and identifier is required.")
    try:
        UUID(source["uuid"])
    except (KeyError, ValueError, TypeError, AttributeError):
        raise PsirtError("A valid attribute UUID is required.") from None
    kind, value = _identifier(source.get("value"))
    if source["type"] == "vulnerability" and kind != "cve":
        raise PsirtError("Use a text attribute for Cisco advisory IDs and bug IDs.")
    if not isinstance(config, dict):
        raise PsirtError("client_id and client_secret are required in config.")
    credentials = [config.get("client_id"), config.get("client_secret")]
    if any(
        not isinstance(item, str) or not 1 <= len(item) <= 4096 or any(not 33 <= ord(c) <= 126 for c in item)
        for item in credentials
    ):
        raise PsirtError("client_id and client_secret must be non-empty printable ASCII credentials.")
    return (
        source,
        kind,
        value,
        *credentials,
        _integer(config, "max_advisories", 20, 100),
        _integer(config, "timeout", 20, 120),
    )


def _text(value, maximum=4096):
    if not isinstance(value, str) or len(value) > maximum:
        raise PsirtError("Cisco PSIRT returned an invalid advisory field.")
    return value.strip()


def _strings(value):
    if value is None:
        return []
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or len(values) > 1000:
        raise PsirtError("Cisco PSIRT returned an invalid advisory list field.")
    return [item for item in (_text(item) for item in values) if item and item.upper() not in ("NA", "N/A")]


def _url(value):
    value = _text(value)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise PsirtError("Cisco PSIRT returned an invalid advisory URL.")
    parsed.port
    return value


def _date(value):
    date = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    return (date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)).isoformat()


def _advisory(row):
    if not isinstance(row, dict):
        raise PsirtError("Cisco PSIRT returned an invalid advisory.")
    kind, advisory_id = _identifier(row.get("advisoryId"))
    if kind != "advisory":
        raise PsirtError("Cisco PSIRT returned an invalid advisory ID.")
    result = {"advisoryId": advisory_id}
    for field, expected in (("cves", "cve"), ("bugIDs", "bugid")):
        result[field] = []
        for item in _strings(row.get(field)):
            kind, identifier = _identifier(item)
            if kind != expected:
                raise PsirtError("Cisco PSIRT returned invalid advisory identifiers.")
            result[field].append(identifier)
    result["cwe"] = _strings(row.get("cwe"))
    if any(not re.fullmatch(r"CWE-[0-9]+", value) for value in result["cwe"]):
        raise PsirtError("Cisco PSIRT returned an invalid CWE identifier.")
    for field in ("productNames", "ipsSignatures"):
        result[field] = _strings(row.get(field))
    for field in ("advisoryTitle", "sir", "status"):
        if row.get(field) not in (None, ""):
            result[field] = _text(row[field])
    if row.get("version") not in (None, ""):
        if type(row["version"]) not in (str, int, float):
            raise PsirtError("Cisco PSIRT returned an invalid advisory version.")
        result["version"] = _text(str(row["version"]))
    for field in ("publicationUrl", "csafUrl"):
        value = row.get(field)
        if value is None or (isinstance(value, str) and value.strip().upper() in ("", "NA", "N/A")):
            continue
        result[field] = _url(value)
    for field in ("firstPublished", "lastUpdated"):
        if row.get(field) not in (None, ""):
            result[field] = _date(row[field])
    score = row.get("cvssBaseScore")
    if score not in (None, "", "NA", "N/A"):
        if type(score) not in (int, float, str) or len(str(score)) > 100:
            raise PsirtError("Cisco PSIRT returned an invalid CVSS score.")
        score = float(score)
        if not math.isfinite(score) or not 0 <= score <= 10:
            raise PsirtError("Cisco PSIRT returned an invalid CVSS score.")
        result["cvssBaseScore"] = score
    if row.get("summary") not in (None, ""):
        soup = BeautifulSoup(_text(row["summary"], 1024 * 1024), "html.parser")
        for element in soup(["script", "style"]):
            element.decompose()
        result["summary"] = soup.get_text(" ", strip=True)
    return result


def _add_objects(event, source, advisory):
    obj = MISPObject("vulnerability")
    obj.comment = "Cisco PSIRT advisory; its CVSS score applies to the advisory as a whole."
    for identifier in dict.fromkeys([advisory["advisoryId"], *advisory["cves"]]):
        obj.add_attribute("id", value=identifier, to_ids=False)
    for field, relation in (
        ("advisoryTitle", "summary"),
        ("summary", "description"),
        ("cvssBaseScore", "cvss-score"),
        ("firstPublished", "published"),
        ("lastUpdated", "modified"),
        ("status", "state"),
    ):
        if field in advisory:
            obj.add_attribute(relation, value=advisory[field], to_ids=False)
    for field in ("publicationUrl", "csafUrl"):
        if field in advisory:
            obj.add_attribute("references", value=advisory[field], to_ids=False)
    obj.add_reference(source["uuid"], "related-to")
    event.add_object(obj)
    _annotation(event, source, {"provider": "Cisco PSIRT", **advisory}, obj.uuid)


def _annotation(event, source, data, advisory_uuid=None):
    obj = MISPObject("annotation")
    obj.comment = "Cisco PSIRT advisory context"
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True), to_ids=False, disable_correlation=True)
    obj.add_reference(source["uuid"], "describes")
    if advisory_uuid:
        obj.add_reference(advisory_uuid, "annotates")
    event.add_object(obj)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise PsirtError("A JSON object is required.")
        source, kind, value, client_id, secret, limit, timeout = _settings(request)
        with requests.Session() as session:
            session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/cisco_psirt"})
            identity, token = _token(session, client_id, secret, timeout)
            try:
                data = _request(
                    session,
                    "GET",
                    f"{API_URL}/{kind}/{value}",
                    timeout,
                    missing=True,
                    auth=_Auth(token),
                    params={"summaryDetails": "true", "productNames": "true"},
                )
            except PsirtError as exc:
                if exc.status == 401:
                    with _TOKEN_LOCK:
                        if _TOKENS.get(identity, (None,))[0] == token:
                            _TOKENS.pop(identity, None)
                raise
        rows = [] if data is None else data.get("advisories")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise PsirtError("Cisco PSIRT returned an invalid advisories collection.")
        # The bug-ID endpoint documents partial matches. Retain only exact IDs.
        selected, filtered = [], 0
        for row in rows:
            identifiers = "bugIDs" if kind == "bugid" else "cves"
            if kind in ("bugid", "cve"):
                matches = [_identifier(item)[1] for item in _strings(row.get(identifiers))]
                if value not in matches:
                    if kind == "cve":
                        raise PsirtError("Cisco PSIRT returned an advisory for a different CVE.")
                    filtered += 1
                    continue
            elif row.get("advisoryId") != value:
                raise PsirtError("Cisco PSIRT returned a different advisory ID.")
            selected.append(row)
        event = MISPEvent()
        for row in selected[:limit]:
            _add_objects(event, source, _advisory(row))
        summary = {
            "provider": "Cisco PSIRT",
            "query_type": kind,
            "query": value,
            "returned": len(rows),
            "count": min(len(selected), limit),
            "filtered_partial_matches": filtered,
            "truncated": len(selected) > limit,
            "status": "found" if selected else "not_found",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }
        _annotation(event, source, summary)
        result = {
            "results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]},
            "summary": summary,
        }
        if summary["truncated"]:
            result["warnings"] = [f"Cisco PSIRT returned more than max_advisories={limit}; the result is truncated."]
        return result
    except PsirtError as exc:
        return {"error": str(exc)}
    except requests.RequestException:
        return {"error": "Cisco PSIRT request failed or timed out."}
    except (ValueError, TypeError, KeyError, OverflowError):
        return {"error": "Invalid Cisco PSIRT request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
