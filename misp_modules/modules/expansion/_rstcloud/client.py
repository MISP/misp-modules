"""Shared helpers for the RST Cloud expansion modules.

The modules ride the official ``rstapi`` library (PyPI) for transport, so a
misp-modules deployment just needs ``pip install rstapi``. These helpers cover
config parsing, error unwrapping, and the misp-modules result shape.
"""

from __future__ import annotations

import json
import re

DEFAULT_BASE_URL = "https://api.rstcloud.net/v1"


def api_key_from_config(config: dict | None) -> str:
    """misp-modules passes user config as a dict; accept common key names."""
    config = config or {}
    return (
        config.get("api_key")
        or config.get("apikey")
        or config.get("rst_api_key")
        or ""
    )


def base_url_from_config(config: dict | None) -> str:
    return (config or {}).get("base_url") or DEFAULT_BASE_URL


def rst_kwargs(config: dict | None) -> dict:
    """Constructor kwargs shared by every rstapi client."""
    return {"APIKEY": api_key_from_config(config), "APIURL": base_url_from_config(config)}


def scan_kwargs(config: dict | None) -> dict:
    """Constructor kwargs for rstapi.scan, extending rst_kwargs with an optional read timeout.

    Scan endpoints (ssl/html/favicon/screenshot/cs-beacon) are synchronous: the RST
    Cloud server connects to the target during your request, so they can take much
    longer than a database lookup.  The default rstapi READ timeout is 20 s, which
    is sometimes not enough.  Set ``timeout`` in the module config (seconds, default
    60) to override it.
    """
    kw = rst_kwargs(config)
    try:
        kw["READ"] = max(1, int((config or {}).get("timeout") or 60))
    except (ValueError, TypeError):
        kw["READ"] = 60
    return kw


def value_from_request(request: dict, keys) -> str | None:
    """Pull the indicator value from a misp-modules request (attribute or typed).

    Handles all three shapes MISP sends: a full ``attribute`` object, a typed
    top-level key (incl. composites like ``ip-dst|port``), and object-level
    enrichment where the value lives in ``object["Attribute"]``.
    """
    if request.get("attribute"):
        return request["attribute"].get("value")
    for key in keys:
        if request.get(key):
            return request[key]
    obj = request.get("object")
    if isinstance(obj, dict):
        wanted = set(keys)
        for a in obj.get("Attribute") or []:
            if a.get("type") in wanted and a.get("value"):
                return a["value"]
    return None


def host_only(value):
    """Strip a MISP composite ``|port`` suffix, returning the bare host/indicator.

    Used by the lookup modules (ioc / noise-control / whois) where the API keys
    on the value itself and the port is irrelevant.
    """
    if not value:
        return value
    return str(value).split("|", 1)[0].strip()


_PORT_SUFFIX = re.compile(r":\d{1,5}$")
_PORT_RELATIONS = ("dst-port", "src-port", "port")


def _join_host_port(host: str, port) -> str:
    """host:port, bracketing IPv6 literals so the colons aren't ambiguous."""
    if host.count(":") >= 2 and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _has_explicit_port(host: str) -> bool:
    # "1.2.3.4:443" / "host:443" — but not a bare IPv4 or IPv6 literal.
    return bool(_PORT_SUFFIX.search(host)) and host.count(":") == 1


def _sibling_port(request) -> str | None:
    """Port taken from a sibling attribute when MISP passes the whole object.

    An ``ip-port`` object stores the port as its own attribute (object_relation
    ``dst-port`` / ``src-port`` / ``port``); when MISP includes ``object`` in the
    request, pick it up so the user doesn't have to set one.
    """
    obj = request.get("object")
    if not isinstance(obj, dict):
        return None
    for a in obj.get("Attribute") or []:
        rel = (a.get("object_relation") or "").lower()
        typ = (a.get("type") or "").lower()
        if (rel in _PORT_RELATIONS or typ == "port") and a.get("value"):
            return str(a["value"]).strip()
    return None


def scan_target(request, inputs, config, *, as_url=False, default_port=None, default_scheme="https"):
    """Build a Scan-API target from a MISP attribute, honouring an optional port.

    IP/host attributes carry no port, but the Scan API addresses a *service*:
    ``host:port`` for ssl / cs-beacon / favicon, or a URL for html / screenshot.
    Port resolution, most specific first:

      1. an explicit port already in the value (``1.2.3.4:8443`` or a URL),
      2. a MISP ``host|port`` composite value (e.g. an ``ip-dst|port`` attribute),
      3. a sibling port attribute in the same MISP object (``ip-port`` object),
      4. the optional ``port`` set in the module config,
      5. ``default_port`` (module-specific fallback, may be ``None``).

    For URL endpoints (``as_url=True``) a bare host becomes
    ``<scheme>://host[:port]`` where scheme is the config ``scheme`` or
    ``default_scheme``. Returns ``None`` when no value is present.
    """
    raw = value_from_request(request, inputs)
    if not raw:
        return None
    raw = str(raw).strip()
    cfg = config or {}

    if raw.startswith(("http://", "https://")):
        return raw  # already a full URL — it encodes its own port

    # Port, most specific source first.
    port = None
    if "|" in raw:  # MISP composite "host|port"
        host, _, p = raw.partition("|")
        raw, port = host.strip(), (p.strip() or None)
    port = port or _sibling_port(request) or (cfg.get("port") or None)

    has_port = _has_explicit_port(raw)  # value was already "host:port"
    if as_url:
        scheme = (cfg.get("scheme") or default_scheme).strip().lower()
        host = raw if has_port or not port else _join_host_port(raw, port)
        return f"{scheme}://{host}"

    # host:port endpoints (ssl / cs-beacon / favicon)
    if has_port:
        return raw
    p = port or default_port
    return _join_host_port(raw, p) if p else raw


def unwrap(resp):
    """Return (data, None) or (None, error_message) for an rstapi response."""
    if isinstance(resp, dict) and resp.get("status") == "error":
        return None, str(resp.get("message", "RST Cloud API error"))
    return resp, None


def error(message: str) -> dict:
    return {"error": message}


# Threat-suffix → (built-in MISP galaxy predicate, RST library galaxy stix_type).
# Kept in sync with rstmisp.misp.tagging; duplicated here so the modules stay
# droppable into misp-modules standalone. The 2nd element selects which RST custom
# galaxy (rst-<stix_type>) a name belongs to when resolving the real cluster tag.
_THREAT_SUFFIX = {
    "_group": ("misp-galaxy:threat-actor", "intrusion-set"),
    "_actor": ("misp-galaxy:threat-actor", "intrusion-set"),
    "_tool": ("misp-galaxy:tool", "tool"),
    "_stealer": ("misp-galaxy:stealer", "malware"),
    "_backdoor": ("misp-galaxy:backdoor", "malware"),
    "_ransomware": ("misp-galaxy:ransomware", "malware"),
    "_miner": ("misp-galaxy:cryptominers", "malware"),
    "_exploit": ("misp-galaxy:exploit-kit", "malware"),
    "_botnet": ("misp-galaxy:botnet", "malware"),
    "_rat": ("misp-galaxy:rat", "malware"),
    "_campaign": ("misp-galaxy:campaign", "campaign"),
}
# Names with no recognised suffix are malware families.
_THREAT_DEFAULT = ("misp-galaxy:malware", "malware")

# RST custom galaxy types in MISP (namespace rstcloud); galaxy stix_type = type[4:].
_RST_GALAXY_TYPES = ("rst-malware", "rst-tool", "rst-intrusion-set", "rst-campaign")

# Per-process caches: a misp-modules worker is long-lived, so reuse the PyMISP
# client + resolved galaxy ids across calls instead of reconnecting every hover.
_RESOLVER_CACHE: dict = {}


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class _RstClusterResolver:
    """Resolve an RST threat ``(stix_type, name)`` to its MISP cluster's real
    ``tag_name`` (``misp-galaxy:rst-*="<cluster-uuid>"``), so an enrichment tag
    attaches the RST Threat Library galaxy — the same node the library/reports/
    feed connectors use. MISP stores a CUSTOM cluster's tag keyed on the UUID, not
    the name, so the value-form ``rstcloud:rst-*="name"`` would not link.

    Targeted ``search_galaxy_clusters`` per name (a handful per enrichment call),
    not a full galaxy pull; per-name results are memoised on the instance.
    """

    def __init__(self, misp, galaxy_ids: dict):
        self._misp = misp
        self._ids = galaxy_ids
        self._cache: dict = {}

    def __call__(self, stix_type: str, name_lower: str):
        gid = self._ids.get("rst-" + stix_type)
        if not gid:
            return None
        key = (stix_type, name_lower)
        if key not in self._cache:
            self._cache[key] = self._lookup(gid, name_lower)
        return self._cache[key]

    def _lookup(self, gid, name_lower):
        try:
            clusters = self._misp.search_galaxy_clusters(
                gid, context="all", searchall=name_lower, pythonify=False
            )
        except Exception:
            return None
        for c in clusters or []:
            gc = c.get("GalaxyCluster", c)
            tname = gc.get("tag_name")
            if not tname:
                continue
            if (gc.get("value") or "").lower() == name_lower:
                return tname
            for el in gc.get("GalaxyElement") or []:
                if el.get("key") == "synonyms" and (el.get("value") or "").lower() == name_lower:
                    return tname
        return None


def rst_resolver_from_config(config: dict | None):
    """Build an RST cluster resolver from optional MISP config, or None.

    Needs ``misp_url`` + ``misp_key`` in the module config; without them (the
    default standalone deployment) returns None and ``threat_tags`` falls back to
    built-in galaxy tags. PyMISP is imported lazily so the modules still install
    with just ``rstapi`` when MISP resolution isn't configured.
    """
    config = config or {}
    url = config.get("misp_url")
    key = config.get("misp_key")
    if not url or not key:
        return None
    if url in _RESOLVER_CACHE:
        return _RESOLVER_CACHE[url]
    try:
        from pymisp import PyMISP
    except Exception:
        return None
    try:
        misp = PyMISP(url, key, ssl=_truthy(config.get("misp_verifycert", False)))
        ids = {}
        for g in misp.galaxies(pythonify=False) or []:
            gd = g.get("Galaxy", g)
            if gd.get("type") in _RST_GALAXY_TYPES and gd.get("id"):
                ids.setdefault(gd["type"], gd["id"])
    except Exception:
        return None
    resolver = _RstClusterResolver(misp, ids)
    _RESOLVER_CACHE[url] = resolver
    return resolver


def threat_tags(threats, rst_resolver=None) -> list:
    """Map RST threat names to MISP galaxy tags (best-effort, suffix-driven).

    When ``rst_resolver`` is supplied (built from MISP config), each name first
    resolves to its RST Threat Library cluster's real ``tag_name`` so the tag
    attaches that galaxy; on a miss (or when no resolver) it falls back to the
    built-in ``misp-galaxy:*`` value-form tag. ``rst_resolver`` is any callable
    ``(stix_type, name_lower) -> tag_name | None``.
    """
    tags = []
    for threat in threats or []:
        if threat.endswith(("_technique", "_vuln")):
            continue
        predicate, stix_type = _THREAT_DEFAULT
        name = threat
        for suffix, (pred, st) in _THREAT_SUFFIX.items():
            if threat.endswith(suffix):
                predicate, stix_type, name = pred, st, threat[: -len(suffix)]
                break
        clean = name.replace("_", " ")
        tag = None
        if rst_resolver:
            try:
                tag = rst_resolver(stix_type, clean.lower())
            except Exception:
                tag = None
        tags.append(tag or f'{predicate}="{clean}"')
    return tags


def scan_group(request, source):
    """uuid that scan-result objects should reference, so each result stays tied
    to exactly what was enriched — without spawning extra container objects.

      1. the parent object, when MISP includes it in the request (``object``);
      2. otherwise the enriched source attribute itself.

    A screenshot / certificate / fetched body cannot be an *attribute* of a
    ``url`` / ``ip-port`` / ``domain-ip`` object — MISP object templates are fixed
    and have no such relation — so each is returned as its own object that
    references this anchor (``identifies`` / ``screenshot-of`` / …). Returns the
    anchor uuid, or ``None`` (typed-key request with no attribute to point at).
    """
    obj = request.get("object")
    if isinstance(obj, dict) and obj.get("uuid"):
        return obj["uuid"]
    return source.uuid if source is not None else None


def misp_event_with_source(request):
    """Start a ``MISPEvent`` seeded with the triggering attribute.

    Returns ``(event, source_attribute_or_None)``. Enrichment objects/attributes
    added to the event can ``add_reference(source.uuid, ...)`` so MISP links them
    to the attribute the analyst enriched. Requires pymisp, which is always
    present in a misp-modules deployment (it's a core dependency).
    """
    from pymisp import MISPAttribute, MISPEvent

    event = MISPEvent()
    source = None
    attr = request.get("attribute")
    if attr:
        source = MISPAttribute()
        source.from_dict(**attr)
        event.add_attribute(**source)
    return event, source


def new_enrichment_object(name):
    """Build a ``MISPObject`` for an RST enrichment template.

    Returns ``(object, dedicated)``. Uses the ``rst-*`` template from the MISP
    object library (install via [MISP/misp-objects](https://github.com/MISP/misp-objects),
    e.g. [PR #526](https://github.com/MISP/misp-objects/pull/526)). Falls back to
    a generic ``annotation`` object if the template is not installed yet, so output
    stays valid misp_standard on any MISP.
    """
    from pymisp import MISPObject

    try:
        obj = MISPObject(name)
        if getattr(obj, "_known_template", False):
            return obj, True
    except Exception:
        pass
    return MISPObject("annotation"), False


def standard_results(event) -> dict:
    """Serialise a ``MISPEvent`` into the misp_standard expansion result envelope."""
    parsed = json.loads(event.to_json())
    return {"results": {k: parsed[k] for k in ("Attribute", "Object") if parsed.get(k)}}


def text_result(value: str, comment: str = "") -> dict:
    """A misp_standard 'nothing structured to return' fallback (one text attribute)."""
    attr = {"type": "text", "value": value}
    if comment:
        attr["comment"] = comment
    return {"results": {"Attribute": [attr]}}


_PYMISP_CACHE: dict = {}


def _pymisp(cfg):
    """Cached PyMISP client from module config (misp_url/misp_key), or None.

    Reused across calls (a misp-modules worker is long-lived). Returns None when
    creds are absent or PyMISP can't connect, so callers degrade gracefully.
    """
    url, key = cfg.get("misp_url"), cfg.get("misp_key")
    if not (url and key):
        return None
    ck = (url, key, bool(_truthy(cfg.get("misp_verifycert", False))))
    if ck in _PYMISP_CACHE:
        return _PYMISP_CACHE[ck]
    try:
        from pymisp import PyMISP
        client = PyMISP(url, key, ssl=ck[2])
    except Exception:
        return None
    _PYMISP_CACHE[ck] = client
    return client


def apply_to_source_attribute(config, request, *, tags=None, comment_note=None,
                              comment_prefix=None, replace_tag_prefixes=(),
                              set_to_ids=None, fp_sightings=0):
    """Write enrichment back ONTO the enriched attribute via the MISP API.

    MISP enrichment itself can only ADD new attributes/objects — it can't modify
    the attribute you ran the module on. So, *only when* ``misp_url``/``misp_key``
    are set in the module config, this updates the source attribute in place:

      * removes the module's own prior tags (``replace_tag_prefixes``) then adds
        ``tags`` — so re-running replaces rather than stacks verdicts;
      * appends ``comment_note`` to the existing comment (dropping any previous
        note that started with ``comment_prefix``, so re-runs stay tidy);
      * sets ``to_ids`` when ``set_to_ids`` is not None;
      * adds ``fp_sightings`` false-positive sightings (type 1) — a benign signal
        that feeds MISP's decay/scoring.

    Returns True if it wrote back (caller should then return an empty result so no
    duplicate attribute is created); False otherwise (caller returns normally).
    """
    cfg = config or {}
    attr = request.get("attribute") or {}
    uuid = attr.get("uuid")
    misp = _pymisp(cfg)
    if not (uuid and misp):
        return False
    try:
        full = misp.get_attribute(uuid, pythonify=True)
    except Exception:
        return False
    try:
        changed = False
        if comment_note is not None:
            existing = (getattr(full, "comment", None) or attr.get("comment") or "")
            segments = [s for s in existing.split(" | ")
                        if s and not (comment_prefix and s.startswith(comment_prefix))]
            segments.append(comment_note)
            full.comment = " | ".join(segments)
            changed = True
        if set_to_ids is not None:
            full.to_ids = bool(set_to_ids)
            changed = True
        if changed:
            misp.update_attribute(full)
        if replace_tag_prefixes:
            for t in getattr(full, "tags", []) or []:
                name = getattr(t, "name", "") or ""
                if any(name.startswith(p) for p in replace_tag_prefixes):
                    misp.untag(uuid, name)
        for tag in tags or []:
            misp.tag(uuid, tag)
        if fp_sightings:
            from pymisp import MISPSighting
            for _ in range(int(fp_sightings)):
                sighting = MISPSighting()
                sighting.from_dict(type="1", source="RST Noise Control")  # 1 = false-positive
                misp.add_sighting(sighting, attribute=uuid)
        return True
    except Exception:
        return False
