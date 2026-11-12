"""Look up exact Wikidata labels and aliases and return related MISP annotations."""

import json
import re
from urllib.error import URLError
from uuid import UUID

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError
from SPARQLWrapper import JSON, POST, SPARQLWrapper
from SPARQLWrapper.SPARQLExceptions import SPARQLWrapperException

mispattributes = {"input": ["text"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "Roman Graf, MISP Project",
    "description": "Look up Wikidata labels and aliases and return related annotation objects.",
    "module-type": ["expansion", "hover"],
    "name": "Wikidata Lookup",
    "logo": "wikidata.png",
    "requirements": ["SPARQLWrapper", "pymisp"],
    "features": (
        "Looks up exact labels and aliases in Wikidata without an API key. Returns bounded candidate matches with"
        " labels, descriptions and Wikidata links as annotation objects related to the source text attribute."
        " Generated attributes have to_ids=false. language defaults to en; max_results defaults to 5 (1-25);"
        " timeout defaults to 15 seconds (1-60). Blank settings use defaults. Labels and descriptions fall back"
        " to English when unavailable in the requested language. No matches returns an empty Object list."
        " Legacy top-level text requests are accepted, but all responses use misp_standard."
    ),
    "references": ["https://www.wikidata.org", "https://www.wikidata.org/wiki/Wikidata:SPARQL_query_service"],
    "input": "A text attribute containing type, value and UUID; legacy top-level text is also accepted.",
    "output": "Annotation objects with Wikidata links, labels and descriptions, in MISP standard format.",
}
moduleconfig = ["language", "max_results", "timeout"]
wiki_api_url = "https://query.wikidata.org/sparql"


class ModuleError(ValueError):
    pass


def _integer_setting(config, name, default, maximum):
    value = config.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    try:
        number = int(value)
    except ValueError:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.") from None
    if not 1 <= number <= maximum:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    return number


def _query(text, language, max_results, timeout):
    # JSON string escaping also produces a SPARQL string literal: it escapes
    # quotes, backslashes, newlines and other controls. Keep Unicode intact to
    # avoid surrogate-pair escapes for characters outside the BMP (PR #869).
    literal = json.dumps(text, ensure_ascii=False)
    query = f"""PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
PREFIX wikibase: <http://wikiba.se/ontology#>
PREFIX bd: <http://www.bigdata.com/rdf#>
SELECT ?item ?itemLabel ?itemDescription WHERE {{
  {{ SELECT DISTINCT ?item WHERE {{
      {{ ?item rdfs:label {literal}@{language} . }}
      UNION
      {{ ?item skos:altLabel {literal}@{language} . }}
      FILTER(REGEX(STR(?item), "^https?://www[.]wikidata[.]org/entity/Q[1-9][0-9]*$"))
    }} ORDER BY ?item LIMIT {max_results}
  }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "{language},en" . }}
}}
ORDER BY ?item
"""
    client = SPARQLWrapper(wiki_api_url, agent="MISP-misp-modules/wiki/1.0 (+https://github.com/MISP/misp-modules)")
    client.setQuery(query)
    client.setReturnFormat(JSON)
    client.setMethod(POST)
    client.setTimeout(timeout)
    try:
        payload = client.query().convert()
    except TimeoutError:
        raise ModuleError("Wikidata query timed out. Try again later.") from None
    except (SPARQLWrapperException, URLError, OSError, ValueError, TypeError):
        # Exceptions may contain the query, response body or proxy credentials.
        raise ModuleError("Wikidata query failed. The service may be unavailable or rate-limited.") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ModuleError("Wikidata returned an invalid query response.")
    bindings = payload["results"].get("bindings")
    if not isinstance(bindings, list):
        raise ModuleError("Wikidata returned an invalid query response.")
    return bindings


def _literal(row, name):
    term = row.get(name)
    if isinstance(term, dict) and term.get("type") == "literal" and isinstance(term.get("value"), str):
        return term["value"].strip()
    return ""


def _expand(event, source, bindings, max_results):
    seen = set()
    for row in bindings:
        if not isinstance(row, dict) or not isinstance(row.get("item"), dict):
            continue
        item = row["item"]
        uri = item.get("value")
        if item.get("type") != "uri" or not isinstance(uri, str):
            continue
        match = re.fullmatch(r"https?://www\.wikidata\.org/entity/(Q[1-9][0-9]*)", uri)
        if match is None or match[1] in seen:
            continue
        qid = match[1]
        seen.add(qid)
        label = _literal(row, "itemLabel")
        description = _literal(row, "itemDescription")
        annotation = MISPObject("annotation")
        annotation.comment = "Wikidata candidate matched by an exact label or alias; review relevance."
        annotation.add_attribute("ref", value=f"https://www.wikidata.org/wiki/{qid}", to_ids=False)
        annotation.add_attribute(
            "text",
            value=(f"{label} ({qid})" if label and label != qid else qid) + (f"\n{description}" if description else ""),
            to_ids=False,
            disable_correlation=True,
        )
        if source is not None:
            annotation.add_reference(source.uuid, "related-to")
        event.add_object(annotation)
        if len(seen) >= max_results:
            break
    if bindings and not seen:
        raise ModuleError("Wikidata returned no valid entity bindings.")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        event = MISPEvent()
        source = None
        if "attribute" in request:
            attribute = request["attribute"]
            if not isinstance(attribute, dict) or attribute.get("type") != "text":
                raise ModuleError("A text attribute containing type, value and UUID is required.")
            if not isinstance(attribute.get("uuid"), str):
                raise ModuleError("A valid source attribute UUID is required.")
            UUID(attribute["uuid"])
            text = attribute.get("value")
        else:
            attribute = None
            text = request.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 2000:
            raise ModuleError("Query text must contain between 1 and 2000 characters.")
        text.encode("utf-8")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        language = config.get("language")
        if language is None or (isinstance(language, str) and not language.strip()):
            language = "en"
        if not isinstance(language, str) or not re.fullmatch(r"[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*", language):
            raise ModuleError("language must be a language tag such as en, fr or zh-hans.")
        language = language.lower()
        max_results = _integer_setting(config, "max_results", 5, 25)
        timeout = _integer_setting(config, "timeout", 15, 60)
        if attribute is not None:
            source = event.add_attribute(**attribute)
        bindings = _query(text, language, max_results, timeout)
        _expand(event, source, bindings, max_results)
        data = json.loads(event.to_json())
        return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, OverflowError, PyMISPError):
        return {"error": "Invalid request, source attribute or Wikidata configuration."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
