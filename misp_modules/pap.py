"""Optional PAP:RED enforcement at the module service boundary."""

# Follow MISP containers only: arbitrary values, descriptions and configuration
# must not be interpreted as intelligence markings.
CONTEXT_KEYS = frozenset({"attribute", "Attribute", "object", "Object", "event", "Event"})
TAG_KEYS = frozenset({"tags", "Tag", "AttributeTag", "ObjectTag", "EventTag"})


def _has_red_tag(tags) -> bool:
    pending = [tags]
    while pending:
        tag = pending.pop()
        if isinstance(tag, str):
            if tag.strip().casefold() == "pap:red":
                return True
        elif isinstance(tag, list):
            pending.extend(tag)
        elif isinstance(tag, dict):
            pending.extend(tag[key] for key in ("name", "Tag") if key in tag)
    return False


def has_pap_red(payload: dict) -> bool:
    """Check supplied attribute, object and event tags, including MISP wrappers.

    Parent markings must be supplied by the caller. The service cannot retrieve
    missing event/object context from an attribute ID or a bare value.
    """
    pending = [payload]
    while pending:
        context = pending.pop()
        if isinstance(context, list):
            pending.extend(context)
        elif isinstance(context, dict):
            if any(_has_red_tag(context[key]) for key in TAG_KEYS if key in context):
                return True
            pending.extend(context[key] for key in CONTEXT_KEYS if key in context)
    return False


def pap_red_error(module, payload: dict) -> str | None:
    """Return a policy error before execution, or None when expansion is allowed.

    Only trusted module metadata can declare an internal source. Missing or
    unrecognised source declarations are treated as external. Call this only
    for expansion modules, and only when the global policy is enabled.
    """
    if not has_pap_red(payload):
        return None
    version = getattr(module, "version", None)
    metadata = version() if callable(version) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    module_types = metadata.get("module-type", [])
    hover_only = isinstance(module_types, list) and "hover" in module_types and "expansion" not in module_types
    if payload.get("hover") is True or hover_only:
        return "Hover expansion blocked by the PAP:RED policy."
    if metadata.get("data-source") != "internal":
        return "External expansion blocked by the PAP:RED policy."
    return None
