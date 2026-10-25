import json
import re
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["cpe"], "format": "misp_standard"}
moduleconfig = ["api_url", "timeout", "max_pages"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "GCVE CPE",
    "description": (
        "Expand CPE attributes with GCVE CPE catalog metadata, package mappings and vulnerability references."
    ),
    "module-type": ["expansion", "hover"],
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Query the public CPE Editor API without an API key. Search results are checked for an exact CPE URI match. "
        "Catalog metadata, deprecation information and PURL mappings are retained in a related annotation. "
        "Vulnerability references become vulnerability objects with their cpe_applicability and rationale preserved. "
        "Only references marked vulnerable populate vulnerable-configuration; other applicability states are context. "
        "api_url defaults to https://cpe.gcve.eu (instance root, without /api); timeout defaults to 30 seconds "
        "per request (maximum 120); max_pages defaults to 5 (1-20), with 100 search results per page. "
        "Blank or null settings use defaults. CPE 2.3 and URI bindings are looked up literally, without conversion."
    ),
    "references": ["https://cpe.gcve.eu/api/docs", "https://cpe.gcve.eu/api/openapi.yaml"],
    "input": "CPE attribute.",
    "output": "A catalog annotation and related vulnerability objects in MISP standard format.",
}
API_URL = "https://cpe.gcve.eu"
APPLICABILITY = {"vulnerable", "not_vulnerable", "requires_configuration", "under_investigation"}


class ModuleError(ValueError):
    pass


def _get(url, params, timeout):
    try:
        response = requests.get(url, params=params, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        raise ModuleError("GCVE CPE API request failed or timed out.") from None
    if response.status_code != 200:
        raise ModuleError(f"GCVE CPE API returned HTTP {response.status_code}.")
    try:
        data = response.json()
    except ValueError:
        raise ModuleError("GCVE CPE API returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise ModuleError("GCVE CPE API returned an invalid response.")
    return data


def _find_cpe(base_url, value, timeout, max_pages):
    # /api/cpes is a substring search (including SQL LIKE wildcards), not an exact lookup.
    for page in range(1, max_pages + 1):
        data = _get(f"{base_url}/api/cpes", {"q": value, "page": page, "per_page": 100}, timeout)
        items, total_pages = data.get("items"), data.get("total_pages")
        if (
            not isinstance(items, list)
            or isinstance(total_pages, bool)
            or not isinstance(total_pages, int)
            or total_pages < 0
            or (total_pages == 0 and items)
            or any(not isinstance(item, dict) or not isinstance(item.get("cpe_uri"), str) for item in items)
        ):
            raise ModuleError("GCVE CPE API returned an invalid search response.")
        for item in items:
            if item["cpe_uri"] == value:
                return item
        if page >= total_pages:
            return None
    raise ModuleError("No exact CPE match within max_pages; increase max_pages to search further.")


def _expand(event, attribute, entry, base_url):
    cpe_id = entry.get("id")
    if isinstance(cpe_id, bool) or not isinstance(cpe_id, int) or cpe_id < 1:
        raise ModuleError("GCVE CPE API returned an invalid CPE entry ID.")
    references = entry.get("vulnerability_references", [])
    if not isinstance(references, list):
        raise ModuleError("GCVE CPE API returned invalid vulnerability references.")
    url = f"{base_url}/cpes/{cpe_id}"
    annotation = MISPObject("annotation")
    annotation.comment = "GCVE CPE catalog metadata (exact URI match)"
    annotation.add_attribute(
        "text", value=json.dumps(entry, sort_keys=True, indent=2), to_ids=False, disable_correlation=True
    )
    annotation.add_attribute("ref", value=url, to_ids=False)
    annotation.add_reference(attribute["uuid"], "describes")
    event.add_object(annotation)
    seen = set()
    for reference in references:
        if (
            not isinstance(reference, dict)
            or not isinstance(reference.get("vulnerability_id"), str)
            or not reference["vulnerability_id"].strip()
            or reference.get("cpe_applicability") not in APPLICABILITY
        ):
            raise ModuleError("GCVE CPE API returned an invalid vulnerability reference.")
        key = json.dumps(reference, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        vulnerability = MISPObject("vulnerability")
        status = reference["cpe_applicability"]
        vulnerability.comment = f"GCVE CPE reference; cpe_applicability={status}"
        vulnerability.add_attribute("id", value=reference["vulnerability_id"], to_ids=False)
        vulnerability.add_attribute("references", value=url, to_ids=False)
        vulnerability.add_attribute("state", value=f"cpe_applicability={status}", to_ids=False)
        if reference.get("rationale"):
            vulnerability.add_attribute("description", value=reference["rationale"], to_ids=False)
        if status == "vulnerable":
            vulnerability.add_attribute("vulnerable-configuration", value=entry["cpe_uri"], to_ids=False)
        vulnerability.add_reference(attribute["uuid"], "related-to")
        vulnerability.add_reference(annotation.uuid, "described-by")
        event.add_object(vulnerability)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        attribute = request["attribute"]
        if not all(attribute.get(key) for key in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] != "cpe":
            raise ModuleError("A CPE attribute is required.")
        value = attribute["value"]
        if not isinstance(value, str):
            raise ModuleError("The CPE value must be a string.")
        value = value.strip()
        fields = re.split(r"(?<!\\)(?:\\\\)*:", value)
        if not (
            (value.startswith("cpe:2.3:") and len(fields) == 13 and fields[2] in ("a", "h", "o", "*", "-"))
            or (value.startswith("cpe:/") and 3 <= len(fields) <= 8 and fields[1] in ("/a", "/h", "/o"))
        ):
            raise ModuleError("A CPE 2.3 formatted string or CPE URI is required.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        config = {k: v for k, v in config.items() if v is not None and not (isinstance(v, str) and not v.strip())}
        timeout = float(config.get("timeout", 30))
        pages = config.get("max_pages", 5)
        if isinstance(pages, bool) or not re.fullmatch(r"\d+", str(pages)):
            raise ModuleError("max_pages must be an integer between 1 and 20.")
        max_pages = int(pages)
        if not 0 < timeout <= 120 or not 1 <= max_pages <= 20:
            raise ModuleError("timeout must be between 0 and 120 seconds; max_pages must be between 1 and 20.")
        base_url = str(config.get("api_url", API_URL)).strip().rstrip("/")
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.query or parsed.fragment:
            raise ModuleError("api_url must be an HTTP(S) instance root URL, without a query or fragment.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        entry = _find_cpe(base_url, value, timeout, max_pages)
        if entry is not None:
            _expand(event, attribute, entry, base_url)
        data = json.loads(event.to_json())
        return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError):
        return {"error": "Invalid request, module configuration or GCVE CPE API response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
