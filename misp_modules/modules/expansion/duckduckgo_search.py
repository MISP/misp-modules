import json
import os
from urllib.parse import urlsplit
from uuid import UUID

from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["url", "domain", "hostname", "text"], "format": "misp_standard"}
moduleconfig = ["max_results", "timeout"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "DuckDuckGo Search",
    "description": "Search DuckDuckGo for web references to an attribute without an API key.",
    "module-type": ["expansion"],
    "requirements": ["ddgs>=9.16.1,<10", "pymisp"],
    "features": (
        "Searches the attribute value using the ddgs DuckDuckGo backend, without automatic provider fallback. "
        "Returns annotation objects containing result links, titles and snippets, related to the input attribute. "
        "max_results defaults to 5 (1-25); timeout defaults to 10 seconds (1-60) per search request. "
        "Blank settings use defaults. Searches use the library's us-en region and moderate safe search. "
        "This unofficial search integration can be rate-limited or broken by upstream changes. "
        "The attribute value is sent to DuckDuckGo; result pages are not downloaded. "
        "Search results are references for review, not maliciousness verdicts."
    ),
    "references": ["https://github.com/deedy5/ddgs", "https://github.com/MISP/misp-modules/issues/601"],
    "input": "A URL, domain, hostname or text attribute.",
    "output": "Related annotation objects with search result links, titles and snippets; to_ids is false.",
}


class ModuleError(ValueError):
    pass


def _setting(config, name, default, maximum):
    value = config.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    try:
        result = int(value)
    except ValueError:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.") from None
    if not 1 <= result <= maximum:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    return result


def _search(value, max_results, timeout):
    # Keep discovery working without this optional dependency and give MISP a useful error.
    try:
        from ddgs import DDGS
        from ddgs.exceptions import DDGSException, RatelimitException, TimeoutException
    except ImportError:
        raise ModuleError(
            "DuckDuckGo Search requires ddgs. Install 'ddgs>=9.16.1,<10' in the service environment."
        ) from None

    proxy = os.environ.get("DDGS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    verify = os.environ.get("SSL_CERT_FILE") or True
    try:
        with DDGS(proxy=proxy, timeout=timeout, verify=verify) as client:
            return client.text(value, backend="duckduckgo", max_results=max_results)
    except RatelimitException:
        raise ModuleError("DuckDuckGo rate limit reached. Try again later.") from None
    except TimeoutException:
        raise ModuleError("DuckDuckGo search timed out. Try again later.") from None
    except DDGSException:
        # Do not expose query values, proxy credentials or upstream response bodies.
        raise ModuleError("DuckDuckGo search failed or returned no results. Try again later.") from None


def _expand(event, attribute, rows, max_results):
    if not isinstance(rows, list):
        raise ModuleError("DuckDuckGo returned an invalid search response.")
    seen = set()
    for row in rows[:max_results]:
        if not isinstance(row, dict):
            continue
        url = row.get("href")
        if not isinstance(url, str) or any(character.isspace() for character in url):
            continue
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                continue
            parsed.port
        except ValueError:
            continue
        if url in seen:
            continue
        seen.add(url)
        title, snippet = row.get("title"), row.get("body")
        text = "\n\n".join(item.strip() for item in (title, snippet) if isinstance(item, str) and item.strip())
        annotation = MISPObject("annotation")
        annotation.comment = "DuckDuckGo search result; relevance and content have not been verified."
        annotation.add_attribute("ref", value=url, to_ids=False)
        annotation.add_attribute("text", value=text or url, to_ids=False, disable_correlation=True)
        annotation.add_reference(attribute["uuid"], "related-to")
        event.add_object(annotation)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        attribute = request["attribute"]
        if attribute.get("type") not in mispattributes["input"]:
            raise ModuleError("A URL, domain, hostname or text attribute is required.")
        value = attribute.get("value")
        if not isinstance(value, str) or not value.strip() or len(value) > 2000:
            raise ModuleError("The attribute value must contain between 1 and 2000 characters.")
        if not isinstance(attribute.get("uuid"), str):
            raise ModuleError("A valid attribute UUID is required.")
        UUID(attribute["uuid"])
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        max_results = _setting(config, "max_results", 5, 25)
        timeout = _setting(config, "timeout", 10, 60)
        event = MISPEvent()
        event.add_attribute(**attribute)
        rows = _search(value, max_results, timeout)
        _expand(event, attribute, rows, max_results)
        data = json.loads(event.to_json())
        return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, OverflowError):
        return {"error": "Invalid request, attribute or DuckDuckGo Search configuration."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
