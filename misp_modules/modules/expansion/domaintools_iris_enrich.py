"""DomainTools Iris Enrich using the provider reference query conventions."""

from misp_modules.lib.domaintools_iris import PIVOT_MAP, REFERENCE, enrich

mispattributes = {"input": list(PIVOT_MAP) if "enrich" == "pivot" else ["domain"], "format": "misp_standard"}
moduleconfig = ["username", "api_key", "results_limit"] + (["guided_pivot_threshold"] if "enrich" == "pivot" else [])
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "DomainTools Iris Enrich",
    "description": "Retrieve DomainTools Iris Enrich results using the provider reference field and query conventions.",
    "module-type": ["expansion"] + ([] if "enrich" == "pivot" else ["hover"]),
    "data-source": "external",
    "logo": "domaintools.png",
    "requirements": ["requests", "PyMISP"],
    "features": (
        "See https://misp.github.io/misp-modules/domaintools/ for services, account requirements, limits and result"
        " mapping."
    ),
    "references": [REFERENCE],
    "input": ", ".join(mispattributes["input"]),
    "output": "Referenced domain, WHOIS, DNS, certificate and annotation objects; new attributes use to_ids=false.",
}


def handler(q=False):
    return enrich(q, "enrich")


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
