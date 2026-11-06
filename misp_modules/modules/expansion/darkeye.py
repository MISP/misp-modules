import json
import re
import unicodedata
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent

from . import check_input_attribute

mispattributes = {"input": ["domain", "hostname"], "output": ["text"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "DarkEye",
    "description": "Look up domain exposure metadata in HaveIBeenRansom and Breach House.",
    "module-type": ["expansion"],
    "data-source": "external",
    "name": "DarkEye",
    "logo": "",
    "requirements": ["An API key for HaveIBeenRansom, Breach House, or both."],
    "features": "Returns one DarkEye JSON report as a non-IDS text attribute. Only listing metadata is retained.",
    "references": ["https://darkeye.io/", "https://haveibeenransom.com/howapi", "https://breach.house/docs"],
    "input": "A domain or hostname attribute.",
    "output": "One text attribute with product-labelled records, errors and truncation status.",
}
moduleconfig = ["haveibeenransom_api_key", "breachhouse_api_key", "max_pages", "max_records", "limit", "timeout"]
HIBR = "HaveIBeenRansom"
BH = "Breach House"
HIBR_URL = "https://haveibeenransom.com/api/metadata/domain/"
BH_URL = "https://breach.house/api/v1/search"
BH_CATEGORIES = {"ransomware": "ransomware", "breaches": "breach", "leads": "leads", "stealers": "stealer"}
HIBR_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breach"}


class LookupError(Exception):
    pass


def _text(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).split())[:512]


def _domain(value):
    if not isinstance(value, str):
        raise ValueError
    value = value.strip().lower().rstrip(".").encode("idna").decode("ascii")
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise ValueError
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError
    return value


def _number(config, name, default, maximum):
    value = config.get(name)
    if value in (None, ""):
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError
    value = int(value)
    if not 1 <= value <= maximum:
        raise ValueError
    return value


def _record(product, category, item):
    return {
        "product": product,
        "category": category,
        "id": _text(item.get("id_source") or item.get("victim_id") or item.get("id")),
        "title": _text(item.get("post_title") or item.get("name")),
        "website": _text(item.get("website")),
        "group": _text(item.get("group_name")),
        "country": _text(item.get("country")),
        "discovered": _text(item.get("discovered"))[:10],
    }


def _matches_domain(record, domain):
    website = record["website"]
    if website:
        try:
            parsed = urlsplit(website if "://" in website else "//" + website)
            host = _domain(parsed.hostname)
        except (ValueError, UnicodeError):
            return False
        return host == domain or host.endswith("." + domain)
    return re.search(r"(?<![\w-])" + re.escape(domain) + r"(?![\w-]|\.\w)", record["title"].lower()) is not None


def _get(session, url, key, timeout, params=None):
    try:
        with session.get(
            url,
            params=params,
            headers={
                "Authorization": "Bearer " + key,
                "User-Agent": "MISP-misp-modules/darkeye",
                "Accept": "application/json",
            },
            timeout=timeout,
            allow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise LookupError(f"HTTP {response.status_code}")
            data = response.json()
    except requests.RequestException:
        raise LookupError("Request failed or timed out") from None
    except ValueError:
        raise LookupError("Invalid JSON response") from None
    if not isinstance(data, dict) or data.get("success") is False or "error" in data:
        raise LookupError("Invalid or unsuccessful API response")
    return data


def _hibr(session, domain, key, options):
    records, seen = [], set()
    for page in range(1, options["max_pages"] + 1):
        url = HIBR_URL + domain + (f"/{page}" if page > 1 else "")
        data = _get(session, url, key, options["timeout"])
        items = data.get("sources") if "sources" in data else data.get("results")
        pagination = data.get("pagination", {})
        if not isinstance(items, list) or not isinstance(pagination, dict):
            raise LookupError("Invalid metadata response")
        has_next = data.get("has_next", pagination.get("has_next"))
        if not isinstance(has_next, bool) or any(not isinstance(item, dict) for item in items):
            raise LookupError("Invalid metadata pagination or records")
        for item in items:
            category = HIBR_CATEGORIES.get(_text(item.get("leak_type")), "leak")
            record = _record(HIBR, category, item)
            if not any(record[field] for field in ("id", "title", "website")):
                raise LookupError("Invalid metadata record")
            identity = record["id"] or json.dumps(record, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            if len(records) == options["max_records"]:
                return records, True
            records.append(record)
        if not has_next:
            return records, False
        if len(records) == options["max_records"]:
            return records, True
    return records, True


def _breach_house(session, domain, key, options):
    data = _get(session, BH_URL, key, options["timeout"], {"q": domain, "limit": options["limit"]})
    records, seen, truncated = [], set(), False
    if not any(source in data for source in BH_CATEGORIES):
        raise LookupError("Invalid search response")
    for source, category in BH_CATEGORIES.items():
        if source not in data:
            raise LookupError("Missing search source")
        section = data[source]
        total = None
        if isinstance(section, dict):
            total, section = section.get("total"), section.get("results")
        if not isinstance(section, list) or any(not isinstance(item, dict) for item in section):
            raise LookupError("Invalid search records")
        if total is not None and (type(total) is not int or total < len(section)):
            raise LookupError("Invalid search total")
        truncated |= total > len(section) if total is not None else len(section) >= options["limit"]
        for item in section:
            record = _record(BH, category, item)
            if not _matches_domain(record, domain):
                continue
            identity = (category, record["id"] or json.dumps(record, sort_keys=True))
            if identity in seen:
                continue
            seen.add(identity)
            if len(records) == options["max_records"]:
                truncated = True
            else:
                records.append(record)
    return records, truncated


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "A JSON object is required"}
    if not isinstance(request, dict):
        return {"error": "A JSON object is required"}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": "An attribute with type, value and uuid is required"}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "A domain or hostname attribute is required"}
    try:
        domain = _domain(attribute["value"])
    except (ValueError, UnicodeError):
        return {"error": "A plain domain name is required"}
    config = request.get("config", {})
    if not isinstance(config, dict):
        return {"error": "Configuration must be an object"}
    try:
        options = {
            "max_pages": _number(config, "max_pages", 5, 20),
            "max_records": _number(config, "max_records", 100, 500),
            "limit": _number(config, "limit", 25, 200),
            "timeout": _number(config, "timeout", 30, 120),
        }
    except ValueError:
        return {"error": "Invalid limits: max_pages 1-20, max_records 1-500, limit 1-200, timeout 1-120"}
    products = []
    for name, setting, fetch in [(HIBR, "haveibeenransom_api_key", _hibr), (BH, "breachhouse_api_key", _breach_house)]:
        key = config.get(setting)
        if key is None or key == "":
            continue
        if not isinstance(key, str) or any(ord(c) < 32 or ord(c) > 126 for c in key):
            return {"error": "API keys must be printable ASCII strings"}
        if key.strip():
            products.append((name, key.strip(), fetch))
    if not products:
        return {"error": "Configure haveibeenransom_api_key, breachhouse_api_key, or both"}
    report = {"provider": "DarkEye", "domain": domain, "products": [], "records": [], "errors": [], "truncated": False}
    for name, key, fetch in products:
        try:
            with requests.Session() as session:
                # Impide que .netrc sustituya el token y separa cookies por producto.
                session.trust_env = False
                records, truncated = fetch(session, domain, key, options)
        except LookupError as error:
            report["errors"].append({"product": name, "error": str(error)})
        else:
            report["products"].append(name)
            report["records"].extend(records)
            report["truncated"] |= truncated
    if not report["products"]:
        return {
            "error": "DarkEye lookup failed: " + "; ".join(e["product"] + ": " + e["error"] for e in report["errors"])
        }
    report["count"] = len(report["records"])
    report["status"] = "partial" if report["errors"] or report["truncated"] else "complete"
    event = MISPEvent()
    event.add_attribute(
        "text",
        json.dumps(report, ensure_ascii=False, sort_keys=True),
        category="Other",
        to_ids=False,
        comment="DarkEye domain exposure metadata; listings do not establish maliciousness or a confirmed incident.",
    )
    return {"results": {"Attribute": json.loads(event.to_json())["Attribute"]}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
