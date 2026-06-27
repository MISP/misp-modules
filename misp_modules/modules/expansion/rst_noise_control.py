"""rst_noise_control — check if an indicator is benign/noise (GET /benign/lookup)."""

from __future__ import annotations

import json

import rstapi

from ._rstcloud.client import (
    apply_to_source_attribute,
    error,
    host_only,
    misp_event_with_source,
    new_enrichment_object,
    rst_kwargs,
    scan_group,
    standard_results,
    text_result,
    unwrap,
    value_from_request,
)

misperrors = {"error": "Error"}

_INPUTS = ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha1", "sha256",
           "ip-src|port", "ip-dst|port", "hostname|port", "domain|port"]
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.4",
    "author": "RST Cloud",
    "description": (
        "Check whether a value (IP, domain, URL or hash) is known-good / noise "
        "via RST Noise Control. Returns an rst-noise object (verdict, category) "
        "linked back to the enriched attribute."
    ),
    "module-type": ["expansion", "hover"],
    "name": "RST Cloud Noise Control",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Queries RST Cloud GET /benign/lookup for benign/noisy verdicts. Returns "
        "an rst-noise MISP object with false-positive risk tags. When misp_url and "
        "misp_key are configured, also annotates the source attribute in place "
        "(tags, comment, to_ids, false-positive sightings)."
    ),
    "references": ["https://api.rstcloud.net/", "https://pypi.org/project/rstapi/"],
    "input": "IP, domain, hostname, URL, or hash attribute (incl. host|port composites).",
    "output": "rst-noise MISP object with verdict, category, and risk/noise tags.",
}
# misp_url/misp_key/misp_verifycert (optional): when set the verdict is ALSO
# written directly onto the enriched attribute (tags, comment, to_ids, FP
# sightings) via the MISP API — the annotation object is always returned
# regardless.
moduleconfig = ["api_key", "base_url", "misp_url", "misp_key", "misp_verifycert"]

# Tag families we own — stripped before re-adding so re-runs replace not stack.
_TAG_PREFIXES = ("false-positive:risk=", "rstcloud:noise-control=", "rstcloud:noise-category=")


def _category(reason: str) -> str:
    """'Change Score Shodan/Scanners/Shodan' -> 'Shodan/Scanners/Shodan'."""
    for action in ("Change Score ", "Drop "):
        if reason.startswith(action):
            return reason[len(action):].strip()
    return reason.strip()


def _category_tag(category: str) -> str:
    """First ``/``-delimited segment for ``rstcloud:noise-category`` (lower cardinality).

    Full category path stays in the object/comment text; the tag uses only the
    top-level bucket before the first ``/``.

    Example (md5, ``Drop Ubuntu Server 26.04 LTS/pam_sepermit.so/``)::

        Verdict: BENIGN - known-good
        Category: Ubuntu Server 26.04 LTS/pam_sepermit.so/
        Type: md5
        rstcloud:noise-category="Ubuntu Server 26.04 LTS"
    """
    category = (category or "").strip()
    if not category:
        return category
    return category.split("/", 1)[0].strip()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config")
    if not rst_kwargs(config)["APIKEY"]:
        return error("An RST Cloud API key is required (set api_key in the module config).")
    value = host_only(value_from_request(request, _INPUTS))
    if not value:
        return error("No supported value found in the request.")

    # /benign/lookup always returns HTTP 200 with {value, type, benign, reason}.
    # `benign` is the STRING "true"/"false".  The `reason` prefix encodes action:
    #   "Drop ..."         -> known-good, safe to suppress  (FP risk high)
    #   "Change Score ..." -> noisy infra (scanners/CDN…), reduce score only
    #                         (FP risk medium — do NOT treat as clean)
    # benign=="false" -> unknown / not in database.
    #
    # Example benign md5 (reason "Drop Ubuntu Server 26.04 LTS/pam_sepermit.so/"):
    #   object/comment Category: Ubuntu Server 26.04 LTS/pam_sepermit.so/
    #   tag rstcloud:noise-category="Ubuntu Server 26.04 LTS"
    #   (+ false-positive:risk="high", rstcloud:noise-control="drop")
    data, err = unwrap(rstapi.noisecontrol(**rst_kwargs(config)).ValueLookup(value))
    if err:
        return error(f"RST Noise Control lookup failed: {err}")
    if not isinstance(data, dict):
        return text_result(f"{value}: unexpected response from RST Noise Control", "RST Noise Control")

    benign   = str(data.get("benign", "")).strip().lower() == "true"
    reason   = (data.get("reason") or "").strip()
    ioc_type = (data.get("type") or "").strip()
    category = _category(reason)
    tag_category = _category_tag(category)

    # --- Determine verdict, tags, and write-back actions ---
    if not benign:
        verdict      = "Not flagged"
        detail       = ""   # "Not Found in our database" is the API's constant for unknown — not a category
        tags         = []
        fp_sightings = 0
        set_to_ids   = None
    elif reason.lower().startswith("change score"):
        verdict      = "NOISY - reduce score"
        detail       = category
        tags         = [
            'false-positive:risk="medium"',
            'rstcloud:noise-control="change-score"',
            f'rstcloud:noise-category="{tag_category}"',
        ]
        fp_sightings = 1
        set_to_ids   = None
    else:
        verdict      = "BENIGN - known-good"
        detail       = category
        tags         = [
            'false-positive:risk="high"',
            'rstcloud:noise-control="drop"',
            f'rstcloud:noise-category="{tag_category}"',
        ]
        fp_sightings = 2
        set_to_ids   = False

    # --- Build annotation fallback text ---
    lines = [f"Verdict: {verdict}"]
    if detail:
        lines.append(f"Category: {detail}")
    if ioc_type:
        lines.append(f"Type: {ioc_type}")

    # --- Build MISP result ---
    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    obj, dedicated = new_enrichment_object("rst-noise")
    obj.comment = "RST Noise Control"
    if dedicated:
        tag_target = obj.add_attribute("verdict", value=verdict, to_ids=False)
        if detail:
            obj.add_attribute("category", value=detail, to_ids=False)
        if ioc_type:
            obj.add_attribute("ioc-type", value=ioc_type, to_ids=False)
        obj.add_attribute("benign", value=str(benign).lower(), to_ids=False)
    else:
        obj.add_attribute("type", value="RST Noise Control", to_ids=False)
        tag_target = obj.add_attribute("text", value="\n".join(lines), to_ids=False)
    for tag in tags:
        tag_target.add_tag(tag)
    if anchor:
        obj.add_reference(anchor, "related-to")
    event.add_object(obj)

    # Optional write-back: when MISP creds are configured, ALSO annotate the
    # source attribute in place (tags, comment, to_ids flip, FP sightings).
    # The annotation object is returned regardless.
    apply_to_source_attribute(
        config, request,
        tags=tags,
        comment_note=f"RST Noise Control: {verdict}" + (f" - {detail}" if detail else ""),
        comment_prefix="RST Noise Control:",
        replace_tag_prefixes=_TAG_PREFIXES,
        set_to_ids=set_to_ids,
        fp_sightings=fp_sightings,
    )

    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
