"""Whisper enrichment module for MISP (misp-modules expansion + hover).

Speaks misp-modules' ``misp_standard`` format: the request carries the full
MISP attribute under ``attribute``, and the response returns MISP Attributes
and Objects (built with PyMISP) that MISP ingests onto the event.

Flows (all real — whisper_core queries → converter_to_misp):
- ``ip-src``/``ip-dst``   — one-hop + threat context + network/BGP context
- ``domain``/``hostname`` — 19-query-max categorized flow under a wall-clock
                            budget (``timeout`` setting, default 8s)
- ``AS``                  — normalized one-hop
- hover (request without ``event_id``) — compact single-query threat verdict

Guards: TLP ceiling (``max_tlp``, default tlp:amber+strict) enforced before
any value leaves the box; content-free results ship an honest status note.

misp-modules contract:
- ``introspection()`` advertises accepted input types + the response format.
- ``version()`` returns module metadata + the operator-configurable settings.
- ``handler(q)`` receives one JSON query per enrichment and returns results.
"""

import json
import logging
import math

from whisper_core.exceptions import WhisperAuthError, WhisperClientError, WhisperTlpError, WhisperTransportError
from whisper_core.whisper_client import WhisperClient
from whisper_misp.enrichment import enrich_asn, enrich_domain, enrich_ip, hover_summary
from whisper_misp.tlp import enforce_max_tlp

from . import check_input_attribute, standard_error_message

logger = logging.getLogger("whisper.module")

misperrors = {"error": "Error"}

DEFAULT_API_URL = "https://graph.whisper.security"

# Per-flow attribute-type routing; every advertised input type now has a
# real enrichment path.
_IP_ATTRIBUTE_TYPES = {"ip-src", "ip-dst"}
_DOMAIN_ATTRIBUTE_TYPES = {"domain", "hostname"}
_ASN_ATTRIBUTE_TYPES = {"AS"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain", "hostname", "AS"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.0.1",
    "author": "Whisper",
    "description": (
        "Enrich IPs, domains, and ASNs with threat intelligence and infrastructure context from the Whisper graph."
    ),
    "module-type": ["expansion", "hover"],
    "name": "Whisper",
    "logo": "whisper.png",
    "requirements": ["An access to the Whisper graph API (api_url + api_key)"],
    "features": (
        "The module queries the Whisper graph for the input attribute and "
        "returns related infrastructure (DNS, ASN/BGP, WHOIS) and threat "
        "intelligence context as MISP attributes and objects."
    ),
    "references": ["https://whisper.security"],
    "input": "An IP address, domain, hostname or AS MISP attribute.",
    "output": (
        "MISP attributes and objects with the related infrastructure and "
        "threat intelligence context from the Whisper graph."
    ),
}

# Operator-set values (MISP module settings UI); arrive in q['config'].
# `timeout` (seconds) bounds the domain flow's wall clock — keep it under
# MISP's own Plugin.Enrichment_timeout or MISP kills the request first.
moduleconfig = ["api_url", "api_key", "max_tlp", "timeout"]


def _timeout_from_config(config: dict) -> float | None:
    """Parse the optional `timeout` module setting; invalid values -> default.

    Non-finite values ("inf", "nan", "1e999") are rejected too: an infinite
    per-call timeout reaches socket.settimeout, which raises OverflowError —
    an operator's attempt at "no timeout" must not crash the module.
    """
    raw = config.get("timeout")
    if raw in (None, ""):
        return None
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        logger.warning("ignoring non-numeric timeout setting %r", raw)
        return None
    if not math.isfinite(seconds) or seconds <= 0:
        logger.warning("ignoring non-finite/non-positive timeout setting %r", raw)
        return None
    return seconds


def _enrich_with_whisper(attribute: dict, config: dict, is_hover: bool = False) -> dict:
    """Route an in-scope attribute through the real Whisper enrichment.

    ``is_hover`` selects the compact single-query threat verdict — MISP's
    hover popover needs an instant answer, not the full graph pull.
    """
    # TLP ceiling first — before anything leaves the box. Enriching a
    # marked attribute sends its value to the Whisper API; the operator's
    # max_tlp is the consent boundary for that egress.
    try:
        enforce_max_tlp(attribute, config.get("max_tlp"))
    except WhisperTlpError as exc:
        return {"error": f"Refusing to enrich: {exc}."}

    api_key = config.get("api_key")
    if not api_key:
        return {
            "error": (
                "Whisper module is not configured: set the api_key module "
                "setting (Administration -> Server Settings -> Plugin -> "
                "Enrichment)."
            )
        }
    api_url = config.get("api_url") or DEFAULT_API_URL

    # Every flow is budgeted (issue #15), so in-request retries are always
    # counterproductive: each attempt gets the full per-call timeout and can
    # blow the wall-clock budget several times over — observed live on the
    # domain path. Queries are best-effort where it matters; fail fast.
    client = WhisperClient(api_url=api_url, api_key=api_key, max_retries=0)
    timeout_seconds = _timeout_from_config(config)
    try:
        if is_hover:
            return hover_summary(client, attribute, timeout_seconds=timeout_seconds)
        if attribute["type"] in _DOMAIN_ATTRIBUTE_TYPES:
            return enrich_domain(client, attribute, timeout_seconds=timeout_seconds)
        if attribute["type"] in _ASN_ATTRIBUTE_TYPES:
            return enrich_asn(client, attribute, timeout_seconds=timeout_seconds)
        return enrich_ip(client, attribute, timeout_seconds=timeout_seconds)
    except WhisperAuthError:
        return {"error": "Whisper API rejected the API key - check the api_key module setting."}
    except WhisperTransportError as exc:
        # Covers timeouts, 5xx, and hard 429 rate-limiting — the client's
        # message says which; all mean "retry later".
        return {
            "error": f"Whisper API unavailable - retry later: {exc}",
        }
    except WhisperClientError as exc:
        # Query-level failures (400s): the full detail — which may embed a
        # 500-char API body snippet — goes to the log; the analyst gets a
        # trimmed line.
        logger.error("Whisper query failed: %s", exc)
        detail = str(exc)
        if len(detail) > 200:
            detail = detail[:200] + "… (full detail in the misp-modules log)"
        return {"error": f"Whisper query failed: {detail}"}
    except Exception:  # noqa: BLE001 - the analyst must never see a traceback
        logger.exception("unexpected error in Whisper enrichment")
        return {"error": "Whisper module hit an unexpected error - see the misp-modules log for details."}
    finally:
        client.close()


def handler(q=False):
    """Process one enrichment query."""
    if q is False:
        return False
    request = json.loads(q)

    attribute = request.get("attribute")
    if not attribute or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": f"Attribute type {attribute['type']!r} is not supported by the Whisper module."}

    # MISP's hover endpoint (AttributesController::hoverEnrichment) posts
    # {module, attribute, config} with NO event_id; the expansion flow
    # (EventsController) always includes event_id. Hover gets the compact
    # single-query verdict.
    is_hover = "event_id" not in request

    return _enrich_with_whisper(attribute, request.get("config") or {}, is_hover=is_hover)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
