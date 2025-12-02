import io
import json

from sigma.backends.discovery import getBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.collection import SigmaCollectionParser

misperrors = {"error": "Error"}
mispattributes = {"input": ["sigma"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Christian Studer",
    "module-type": ["expansion", "hover"],
    "name": "Sigma Rule Converter",
    "description": "An expansion hover module to display the result of sigma queries.",
    "logo": "sigma.png",
    "requirements": ["Sigma python library"],
    "features": (
        "This module takes a Sigma rule attribute as input and tries all the different queries available to convert it"
        " into different formats recognized by SIEMs."
    ),
    "references": ["https://github.com/Neo23x0/sigma/wiki"],
    "input": "A Sigma attribute.",
    "output": "Text displaying results of queries on the Sigma attribute.",
}
moduleconfig = []
sigma_targets = (
    "es-dsl",
    "es-qs",
    "graylog",
    "kibana",
    "xpack-watcher",
    "logpoint",
    "splunk",
    "grep",
    "mdatp",
    "splunkxml",
    "arcsight",
    "qualys",
)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("sigma"):
        misperrors["error"] = "Sigma rule missing"
        return misperrors
    config = SigmaConfiguration()
    f = io.TextIOWrapper(io.BytesIO(request.get("sigma").encode()), encoding="utf-8")
    parser = SigmaCollectionParser(f, config)
    targets = []
    results = []
    for t in sigma_targets:
        backend = getBackend(t)(config, {"rulecomment": False})
        try:
            parser.generate(backend)
            result = backend.finalize()
            if result:
                results.append(result)
                targets.append(t)
        except Exception:
            continue
    d_result = {t: r.strip() for t, r in zip(targets, results)}
    return {"results": [{"types": mispattributes["output"], "values": d_result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
