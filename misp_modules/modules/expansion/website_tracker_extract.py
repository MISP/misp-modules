"""Extract publisher identifiers from supplied captures without fetching or executing content."""

import base64
import binascii
import json
import re
from bisect import bisect_right
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4, uuid5

from pymisp import MISPObject

mispattributes = {"input": ["attachment", "text"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Website tracker extract",
    "description": "Extract analytics, advertising, affiliate and publisher identifiers from HTML, scripts or HAR.",
    "module-type": ["expansion"],
    "requirements": ["pymisp"],
    "references": ["https://github.com/MISP/misp-objects/tree/main/objects/tracking-id"],
    "features": (
        "Offline extraction into tracking-id objects with provider-qualified correlation keys, source locations and"
        " references to the input. Supports HAR request URLs, POST data and embedded response bodies, including base64."
        " All extracted attributes use to_ids=false. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/website_tracker_extract.md for"
        " supported providers, input examples, limits and interpretation."
    ),
    "input": "A text attribute or base64 attachment containing captured HTML, JavaScript or HAR 1.2 JSON.",
    "output": "Deduplicated tracking-id objects with raw identifiers and source evidence in their descriptions.",
}

MAX_BYTES = 10 * 1024 * 1024
MAX_DECODED_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_OCCURRENCES = 10000

# Distinctive vendor prefixes may be recognised anywhere. Numeric IDs require
# vendor-specific calls or URLs; generic 'id', 'sid', 'pid' and 'tag' are not evidence.
RULES = [
    ("google-analytics", "analytics", r"(?<![\w-])(?P<id>UA-\d{4,12}-\d{1,4})(?![\w-])"),
    ("google-analytics-4", "analytics", r"(?<![\w-])(?P<id>G-[A-Z0-9]{6,15})(?![\w-])"),
    ("google-tag-manager", "tag-manager", r"(?<![\w-])(?P<id>GTM-[A-Z0-9]{4,15})(?![\w-])"),
    ("google-ads", "advertising", r"(?<![\w-])(?P<id>AW-\d{6,15})(?:/[\w-]+)?(?![\w-])"),
    ("google-adsense", "advertising", r"(?<![\w-])(?:ca-)?(?P<id>pub-\d{16})(?![\w-])"),
    ("meta-pixel", "advertising", r"\bfbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](?P<id>\d{5,20})['\"]"),
    ("hotjar", "analytics", r"\bhjid['\"]?\s*:\s*['\"]?(?P<id>\d{3,12})(?![\w])"),
    ("yandex-metrica", "analytics", r"\bym\s*\(\s*['\"]?(?P<id>\d{3,12})['\"]?\s*,\s*['\"]init['\"]"),
    ("yandex-metrica", "analytics", r"\bYa\.Metrika2?\s*\(\s*\{\s*id\s*:\s*['\"]?(?P<id>\d{3,12})(?![\w])"),
    (
        "microsoft-clarity",
        "analytics",
        r"\bclarity\s*\(\s*['\"]setProjectId['\"]\s*,\s*['\"](?P<id>[a-z0-9]{5,20})['\"]",
    ),
    (
        "microsoft-clarity",
        "analytics",
        r"\(\s*window\s*,\s*document\s*,\s*['\"]clarity['\"]\s*,\s*['\"]script['\"]\s*,\s*['\"](?P<id>[a-z0-9]{5,20})['\"]",
    ),
    ("linkedin-insight", "advertising", r"\b_linkedin_partner_id\s*=\s*['\"](?P<id>\d{3,15})['\"]"),
    ("tiktok-pixel", "advertising", r"\bttq\.load\s*\(\s*['\"](?P<id>[A-Z0-9]{10,30})['\"]"),
    ("amazon-associates", "affiliate", r"\bamzn_assoc_tracking_id\s*=\s*['\"](?P<id>[A-Za-z0-9_-]{1,100}-\d{2})['\"]"),
]
RULES = [(provider, category, re.compile(pattern)) for provider, category, pattern in RULES]
URL_RE = re.compile(r"(?:https?:)?(?:/|\\/){2}[^\s<>\"'`)}\]]+")
AMAZON_HOSTS = {
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "amazon.fr",
    "amazon.it",
    "amazon.es",
    "amazon.ca",
    "amazon.co.jp",
    "amazon.in",
    "amazon.com.au",
    "amazon.com.br",
    "amazon.com.mx",
    "amazon.nl",
    "amazon.se",
    "amazon.pl",
    "amazon.sg",
    "amazon.ae",
    "amazon.sa",
    "amazon.com.tr",
    "amazon.eg",
    "amazon.com.be",
    "amazon.co.za",
}


def decode_base64(value, limit):
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise ValueError("Missing base64 data or attachment exceeds the size limit.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid base64 capture data.") from error
    if len(decoded) > limit:
        raise ValueError("Decoded capture exceeds the size limit.")
    return decoded


def parse_input(query):
    request = json.loads(query)
    if not isinstance(request, dict):
        raise ValueError("Expected a JSON object.")
    attribute = request.get("attribute")
    if attribute is None and "attachment" in request:
        attribute = {"type": "attachment", "value": request["attachment"], "uuid": str(uuid4())}
    if not isinstance(attribute, dict) or attribute.get("type") not in mispattributes["input"]:
        raise ValueError("Expected a text or attachment attribute.")
    if not isinstance(attribute.get("value"), str) or not attribute["value"].strip():
        raise ValueError("The attribute must have a nonempty string value.")
    UUID(attribute.get("uuid", ""))
    attribute = dict(attribute)
    if attribute["type"] == "attachment":
        data = attribute.get("data", request.get("data"))
        raw = decode_base64(data, MAX_BYTES)
        attribute["data"] = data
        text = raw.decode("utf-8-sig", errors="replace")
        filename = attribute["value"]
    else:
        text = attribute["value"]
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise ValueError("Capture exceeds the 10 MiB size limit.")
        filename = "text"
    return attribute, text, filename


def sources(text, filename):
    """Yield decoded HAR fields with unambiguous JSON paths, or a standalone document."""
    if not text.lstrip().startswith(("{", "[")) and not filename.lower().endswith(".har"):
        yield text, filename, None
        return
    try:
        har = json.loads(text)
    except ValueError as error:
        # A JavaScript block may start with '{' without being JSON.
        if not filename.lower().endswith(".har"):
            yield text, filename, None
            return
        raise ValueError("Invalid HAR JSON.") from error
    if not isinstance(har, dict) or "log" not in har:
        if filename.lower().endswith(".har"):
            raise ValueError("Expected a HAR log object.")
        yield text, filename, None
        return
    log = har["log"]
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError("HAR log.entries must be a list of at most 2000 entries.")
    total = 0
    for index, entry in enumerate(entries):
        path = f"log.entries[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid HAR entry at {path}.")
        request, response = entry.get("request", {}), entry.get("response", {})
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError(f"Invalid HAR request/response at {path}.")
        url = request.get("url")
        if url is not None and not isinstance(url, str):
            raise ValueError(f"Invalid HAR request URL at {path}.")
        if url:
            yield url, path + ".request.url", url
        post = request.get("postData", {})
        content = response.get("content", {})
        if not isinstance(post, dict) or not isinstance(content, dict):
            raise ValueError(f"Invalid HAR body at {path}.")
        for body, field in ((post, ".request.postData.text"), (content, ".response.content.text")):
            value = body.get("text")
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"Expected text at {path}{field}.")
            mime = body.get("mimeType", "")
            if not isinstance(mime, str):
                raise ValueError(f"Invalid MIME type at {path}{field}.")
            if mime and not any(
                t in mime.lower() for t in ("text/", "javascript", "json", "xml", "x-www-form-urlencoded")
            ):
                continue
            encoding = body.get("encoding")
            if encoding not in (None, "", "base64"):
                raise ValueError(f"Unsupported HAR body encoding at {path}{field}.")
            raw = decode_base64(value, MAX_DECODED_BYTES) if encoding == "base64" else value.encode("utf-8")
            total += len(raw)
            if total > MAX_DECODED_BYTES:
                raise ValueError("Decoded HAR bodies exceed 20 MiB.")
            yield raw.decode("utf-8-sig", errors="replace"), path + field, url


def url_identifiers(value):
    """Only interpret ambiguous query keys on an explicitly recognised provider host."""
    try:
        parsed = urlsplit("https:" + value if value.startswith("//") else value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in ("http", "https") or not host:
            return
    except ValueError:
        return
    query = parse_qs(parsed.query)
    rules = [
        ("facebook.com", "/tr", "id", "meta-pixel", "advertising", r"\d{5,20}"),
        ("clarity.ms", "/tag/", None, "microsoft-clarity", "analytics", r"[a-z0-9]{5,20}"),
        ("mc.yandex.ru", "/watch/", None, "yandex-metrica", "analytics", r"\d{3,12}"),
        ("awin1.com", "/", "awinaffid", "awin", "affiliate", r"\d{1,15}"),
        ("shareasale.com", "/r.cfm", "u", "shareasale", "affiliate", r"\d{1,15}"),
    ]
    for domain, path, key, provider, category, pattern in rules:
        matches_path = parsed.path.startswith(path) if key is None or path == "/" else parsed.path.rstrip("/") == path
        if (host == domain or host.endswith("." + domain)) and matches_path:
            values = query.get(key, []) if key else [parsed.path[len(path) :].split("/", 1)[0]]
            for identifier in values:
                if re.fullmatch(pattern, identifier):
                    yield provider, category, identifier
    if any(host == domain or host.endswith("." + domain) for domain in AMAZON_HOSTS):
        for identifier in query.get("tag", []):
            if re.fullmatch(r"[A-Za-z0-9_-]{1,100}-\d{2}", identifier):
                yield "amazon-associates", "affiliate", identifier


class VerificationParser(HTMLParser):
    """HTML attributes can appear in either order, with any valid quoting."""

    def __init__(self, record):
        super().__init__(convert_charrefs=True)
        self.record = record

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        attrs = dict(attrs)
        provider = {
            "google-site-verification": "google-site-verification",
            "facebook-domain-verification": "facebook-domain-verification",
            "msvalidate.01": "bing-site-verification",
        }.get((attrs.get("name") or "").lower())
        identifier = attrs.get("content") or ""
        if provider and re.fullmatch(r"[A-Za-z0-9_-]{10,256}", identifier):
            self.record(provider, "site-verification", identifier, self.getpos())


def extract(attribute, text, filename):
    findings = {}
    seen = set()
    count = 0
    for content, path, url in sources(text, filename):
        newlines = [-1] + [match.start() for match in re.finditer("\n", content)]

        def record(provider, category, identifier, position):
            nonlocal count
            line, column = position
            evidence = {"source": path, "line": line, "column": column + 1, "offset": newlines[line - 1] + 1 + column}
            if url:
                evidence["url"] = url
            occurrence = (provider, identifier, path, line, column)
            if occurrence in seen:
                return
            seen.add(occurrence)
            key = (provider, identifier)
            finding = findings.setdefault(key, {"category": category, "identifier": identifier, "sources": []})
            finding["sources"].append(evidence)
            count += 1
            if count > MAX_OCCURRENCES:
                raise ValueError("Capture exceeds the 10000 identifier occurrence limit.")

        def at_offset(provider, category, identifier, offset):
            line = bisect_right(newlines, offset)
            record(provider, category, identifier, (line, offset - newlines[line - 1] - 1))

        for provider, category, pattern in RULES:
            for match in pattern.finditer(content):
                at_offset(provider, category, match["id"], match.start("id"))
        for match in URL_RE.finditer(content):
            normalized = unescape(
                match[0].rstrip("\\").replace("\\/", "/").replace("\\u0026", "&").replace("\\x26", "&")
            )
            for provider, category, identifier in url_identifiers(normalized):
                at_offset(provider, category, identifier, match.start())
        if path.endswith(".request.postData.text") and url:
            # Form-encoded pixel POSTs use the same provider-specific keys as
            # their query strings. The location is the start of the form body.
            try:
                form_url = urlsplit(url)._replace(query=content, fragment="").geturl()
            except ValueError:
                form_url = ""
            for provider, category, identifier in url_identifiers(form_url):
                at_offset(provider, category, identifier, 0)
        parser = VerificationParser(record)
        parser.feed(content)
        parser.close()
    objects = []
    for (provider, identifier), evidence in sorted(findings.items()):
        key = f"{provider}:{identifier}"
        obj = MISPObject("tracking-id", standalone=False)
        obj.uuid = uuid5(UUID(attribute["uuid"]), key)
        obj.add_attribute("id", value=key, to_ids=False, disable_correlation=False)
        obj.add_attribute("tracker", value=provider, to_ids=False, disable_correlation=True)
        obj.add_attribute(
            "description", value=json.dumps(evidence, ensure_ascii=True), to_ids=False, disable_correlation=True
        )
        for url in sorted({source["url"] for source in evidence["sources"] if "url" in source}):
            if url.lower().startswith(("http://", "https://")):
                obj.add_attribute("url", value=url, to_ids=False, disable_correlation=True)
        obj.add_reference(attribute["uuid"], "extracted-from")
        objects.append(json.loads(obj.to_json()))
    return {"results": {"Attribute": [attribute], "Object": objects}}


def handler(q=False):
    if q is False:
        return False
    try:
        return extract(*parse_input(q))
    except (ValueError, TypeError, AttributeError, RecursionError) as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
