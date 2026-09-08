import json
from urllib.parse import urlparse

import requests
from pymisp import MISPEvent

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["text", "url", "link", "other"],
    "output": ["text", "link"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "extuno.com Tolga SEZER",
    "description": (
        "Query Extuno for the reputation of a browser extension, an IDE extension or a package,"
        " identified by its store id or its listing URL."
    ),
    "module-type": ["expansion", "hover"],
    "name": "Extuno Lookup",
    "logo": "extuno.png",
    "requirements": ["An Extuno API key"],
    "features": (
        "The module takes a store listing URL, or a `store:id` pair in a text attribute, and reports"
        " what Extuno knows about that artifact: whether it appears in the known-malicious catalog,"
        " with the threat type and the advisory it came from, and whether Extuno's own static and"
        " sandbox analysis reached a verdict on it.\n\nIt covers browser extensions (Chrome, Firefox,"
        " Edge), IDE extensions (VS Code, JetBrains, Eclipse), Discord client mods and the npm, PyPI,"
        " Packagist, Maven, WordPress and Open VSX registries. Browser and IDE extensions are the"
        " reason the module exists: they are not covered by OSV or any other public advisory"
        " database, so an extension id found on a workstation cannot be checked against one.\n\n"
        "Only the identifier being looked up leaves the MISP instance. The lookup is read-only and"
        " never submits the artifact for analysis."
    ),
    "references": ["https://extuno.com", "https://extuno.com/pip-scanner"],
    "input": "A store listing URL, or a text attribute holding `store:id` (e.g. `chrome:cjpalhd...`).",
    "output": "A text attribute carrying the verdict, and a link to the advisory or store listing.",
}
# The API key is mandatory: the lookup runs against a tenant account. api_url is exposed only so an
# operator can point the module at a self-hosted deployment.
moduleconfig = ["api_key", "api_url"]

DEFAULT_API_URL = "https://extuno.com"
USER_AGENT = "extuno-misp/1.0 (+https://github.com/MISP/misp-modules)"
TIMEOUT = 20

# Store identifiers accepted by the API, and the URL shapes they are published under. The path index
# is where the identifier sits after the marker segment; a negative index counts from the end, which
# is what a trailing-slash-tolerant listing URL needs.
STORES = (
    "chrome", "firefox", "edge", "vscode", "jetbrains", "eclipse", "discord",
    "npm", "pypi", "composer", "maven", "wordpress", "openvsx",
)

# A Chrome or Edge extension id is exactly 32 characters drawn from a-p. Nothing else in a MISP
# event looks like that, so a bare value of that shape is worth resolving without a store prefix.
_WEBSTORE_ID_LENGTH = 32
_WEBSTORE_ID_ALPHABET = set("abcdefghijklmnop")


def _host_is(host, domain):
    """Whether the host is that domain or a subdomain of it.

    str.endswith() is the wrong test: "evil-pypi.org".endswith("pypi.org") is true, which would let a
    lookalike delivery URL inherit the verdict of the legitimate package it is imitating. That URL is
    exactly the kind of indicator a MISP event holds, so the boundary has to be a dot.
    """
    return host == domain or host.endswith("." + domain)


def _webstore_id(value):
    """A Chrome or Edge extension id, or None. The format is exactly 32 characters from a-p."""
    candidate = (value or "").strip().lower()
    if len(candidate) == _WEBSTORE_ID_LENGTH and set(candidate) <= _WEBSTORE_ID_ALPHABET:
        return candidate
    return None


class UnknownArtifact(Exception):
    """The attribute does not name an artifact this module can look up.

    Distinct from an empty answer on purpose: telling an analyst "not known malicious" for a value
    we never managed to parse would be a verdict we did not actually obtain.
    """


def _from_url(value):
    """Resolve a store listing URL to a (store, identifier) pair, or None."""
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]

    def after(marker, offset=1):
        if marker in parts:
            index = parts.index(marker) + offset
            if index < len(parts):
                return parts[index]
        return None

    def webstore(store):
        # .../detail/<slug>/<id>, and older listings omit the slug. Taking whichever segment is
        # present would turn a URL truncated at the slug into a lookup for the slug, so the id is
        # validated rather than assumed.
        return next(((store, found) for found in
                     (_webstore_id(after("detail", 2)), _webstore_id(after("detail", 1))) if found),
                    None)

    if host in ("chromewebstore.google.com", "chrome.google.com"):
        return webstore("chrome")
    if _host_is(host, "microsoftedge.microsoft.com"):
        return webstore("edge")
    if _host_is(host, "addons.mozilla.org"):
        slug = after("addon")
        return ("firefox", slug) if slug else None
    if _host_is(host, "marketplace.visualstudio.com"):
        # itemName=<publisher>.<name> is the only stable identifier here.
        for pair in (parsed.query or "").split("&"):
            if pair.startswith("itemName="):
                item = pair[len("itemName="):]
                return ("vscode", item) if item else None
        return None
    if _host_is(host, "open-vsx.org"):
        publisher, name = after("extension", 1), after("extension", 2)
        return ("openvsx", f"{publisher}.{name}") if publisher and name else None
    if _host_is(host, "plugins.jetbrains.com"):
        # /plugin/<numeric id>-<slug>. A URL carrying only the slug names a plugin this module
        # cannot address, so it is rejected rather than looked up under the slug.
        plugin = (after("plugin") or "").split("-", 1)[0]
        return ("jetbrains", plugin) if plugin.isdigit() else None
    if _host_is(host, "marketplace.eclipse.org"):
        slug = after("content")
        return ("eclipse", slug) if slug else None
    if _host_is(host, "npmjs.com"):
        name = after("package")
        if name and name.startswith("@"):
            # A scope on its own is not a package.
            scoped = after("package", 2)
            return ("npm", f"{name}/{scoped}") if scoped else None
        return ("npm", name) if name else None
    if _host_is(host, "pypi.org"):
        name = after("project")
        return ("pypi", name) if name else None
    if _host_is(host, "packagist.org"):
        vendor, package = after("packages", 1), after("packages", 2)
        return ("composer", f"{vendor}/{package}") if vendor and package else None
    if _host_is(host, "wordpress.org"):
        slug = after("plugins")
        return ("wordpress", slug) if slug else None
    return None


def _resolve(attribute):
    """Work out which store and identifier the attribute names."""
    value = str(attribute.get("value", "")).strip()
    if not value:
        raise UnknownArtifact("the attribute value is empty")

    if value.lower().startswith(("http://", "https://")):
        resolved = _from_url(value)
        if resolved:
            return resolved
        raise UnknownArtifact(f"{value} is not a store listing URL Extuno recognises")

    # An explicit store prefix is unambiguous, so it wins over any shape heuristic.
    if ":" in value:
        store, _, identifier = value.partition(":")
        store = store.strip().lower()
        if store in STORES and identifier.strip():
            return store, identifier.strip()

    bare = _webstore_id(value)
    if bare:
        # Chrome and Edge share this id format, so both are asked and the first hit answers.
        return "chrome", bare

    raise UnknownArtifact(
        "prefix the value with its store (e.g. chrome:cjpalhdlnbpafiamejdnhcphjbkeiagm) "
        "or use the store listing URL"
    )


def _lookup(api_url, api_key, store, identifier):
    try:
        response = requests.get(
            f"{api_url}/v1/lookup",
            params={"store": store, "id": identifier},
            headers={"X-Api-Key": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if response.status_code in (401, 403):
            return {"__error__": "Extuno rejected the API key."}
        if response.status_code == 429:
            return {"__error__": "Extuno rate limit reached; try again shortly."}
        response.raise_for_status()
        body = response.json()
        # A 200 carrying a JSON array or a bare string is not an answer from this API. Returning it
        # would put a stack trace where the module contract expects an error dict.
        return body if isinstance(body, dict) else None
    except (requests.exceptions.RequestException, ValueError):
        return None


class ExtunoParser:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key
        self.misp_event = MISPEvent()
        self.found = False

    def _add(self, **kwargs):
        self.misp_event.add_attribute(**kwargs)
        self.found = True

    def _query(self, store, identifier):
        """One lookup. Returns (payload, failure); exactly one of them is set."""
        result = _lookup(self.api_url, self.api_key, store, identifier)
        if result is None:
            return None, "Extuno could not be reached."
        if result.get("__error__"):
            return None, result["__error__"]
        return result, None

    def parse(self, store, identifier):
        result, failure = self._query(store, identifier)
        if failure:
            return failure

        # A Chrome id and an Edge id are the same 32 characters, so a miss on one is not an answer.
        # The verdict is normalised the same way here as it is below: a response with no verdict, or
        # a null one, is a miss and must reach the fallback like an explicit "unknown" does.
        if store == "chrome" and (result.get("verdict") or "unknown") == "unknown":
            edge, edge_failure = self._query("edge", identifier)
            # A rejected key or a rate limit on the second call is a failed lookup, not a clean
            # answer. Reporting "not in the malicious catalog" for a question that was never
            # answered is the one outcome a reputation module must never produce.
            if edge_failure:
                return edge_failure
            if (edge.get("verdict") or "unknown") != "unknown":
                store, result = "edge", edge

        verdict = result.get("verdict") or "unknown"
        # A field of the wrong type is treated as absent rather than trusted: an operator can point
        # api_url at another deployment, and a proxy can rewrite a body.
        catalog = result.get("catalog") if isinstance(result.get("catalog"), dict) else {}
        scan = result.get("scan") if isinstance(result.get("scan"), dict) else {}

        if result.get("known_malicious"):
            threat = catalog.get("threat_type") or "malicious"
            summary = f"Extuno: {store}:{identifier} is listed as malicious ({threat})"
            if catalog.get("still_active") is False:
                summary += ", removed from the store"
            self._add(type="text", value=summary, comment="Extuno: known-malicious catalog",
                      disable_correlation=True)
            if catalog.get("reason"):
                self._add(type="text", value=f"Extuno: {catalog['reason']}",
                          comment="Extuno: catalog detail", disable_correlation=True)
            if catalog.get("source_url"):
                self._add(type="link", value=catalog["source_url"],
                          comment="Extuno: advisory this listing came from", disable_correlation=True)
        elif verdict != "unknown":
            summary = f"Extuno analysed {store}:{identifier} and reached the verdict {verdict}"
            if result.get("risk_score") is not None:
                summary += f" (risk {result['risk_score']}/100)"
            self._add(type="text", value=summary, comment="Extuno: analysis verdict",
                      disable_correlation=True)
        else:
            # Reported rather than returned as an error: "we looked and it is not on record" is a
            # useful answer, and is not the same as the lookup having failed.
            self._add(
                type="text",
                value=f"Extuno has no record of {store}:{identifier}: not in the malicious catalog "
                      "and not analysed.",
                comment="Extuno: no record", disable_correlation=True)
            return None

        findings = scan.get("top_findings")
        findings = findings if isinstance(findings, list) else []
        for title in [f["title"] for f in findings
                      if isinstance(f, dict) and f.get("title")][:5]:
            self._add(type="text", value=f"Extuno finding: {title}",
                      comment="Extuno: evidence from analysis", disable_correlation=True)
        return None

    def get_results(self):
        if not self.found:
            return {"error": "No Extuno results for this attribute."}
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if event.get(key)}
        if not results:
            return {"error": "No Extuno results for this attribute."}
        return {"results": results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an UUID."}

    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    config = request.get("config") or {}
    api_key = str(config.get("api_key") or "").strip()
    if not api_key:
        return {"error": "An Extuno API key is required; set api_key in the module configuration."}
    api_url = str(config.get("api_url") or DEFAULT_API_URL).rstrip("/")

    try:
        store, identifier = _resolve(attribute)
    except UnknownArtifact as error:
        return {"error": f"Extuno cannot look this up: {error}"}

    parser = ExtunoParser(api_url, api_key)
    # The identifier is passed raw: requests encodes it once as a query parameter. Encoding it here
    # as well would put a literal "%3A" on the wire for a Maven coordinate and look up an artifact
    # that cannot exist.
    failure = parser.parse(store, identifier)
    if failure:
        return {"error": failure}
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
