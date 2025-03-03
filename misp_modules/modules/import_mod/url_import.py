import base64
import json

from pymisp import MISPEvent, MISPObject
from pymisp.tools._psl_faup import PSLFaup as Faup

misperrors = {"error": "Error"}
userConfig = {
    "include_scheme": {"type": "Boolean", "message": "Include scheme"},
}

mispattributes = {
    "inputSource": ["file", "paste"],
    "output": ["MISP Format"],
    "format": "misp_standard",
}


moduleinfo = {
    "version": "0.1",
    "author": "Sami Mokaddem",
    "description": "Simple URL import tool with Faup",
    "module-type": ["import"],
    "name": "URL Import",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

moduleconfig = []

fp = Faup()


def generateData(event, data, config):
    for url in data.splitlines():
        fp.decode(url)
        parsed = fp.get()
        obj = MISPObject("url")
        obj.add_attribute("url", type="url", value=url)
        if parsed["tld"] is not None:
            obj.add_attribute("tld", type="text", value=parsed["tld"])
        if parsed["subdomain"] is not None:
            obj.add_attribute("subdomain", type="text", value=parsed["subdomain"])
        if config["include_scheme"] is True:
            obj.add_attribute("scheme", type="text", value=parsed["scheme"])
        obj.add_attribute("resource_path", type="text", value=parsed["resource_path"])
        obj.add_attribute("query_string", type="text", value=parsed["query_string"])
        obj.add_attribute("port", type="port", value=parsed["port"])
        obj.add_attribute("host", type="hostname", value=parsed["host"])
        if parsed["fragment"] is not None:
            obj.add_attribute("fragment", type="text", value=parsed["fragment"])
        obj.add_attribute("domain_without_tld", type="text", value=parsed["domain_without_tld"])
        obj.add_attribute("domain", type="domain", value=parsed["domain"])
        event.objects.append(obj)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    data = getUploadedData(request)
    config = getPassedConfig(request)
    event = MISPEvent()
    generateData(event, data, config)
    return {"results": json.loads(event.to_json())}


def getUploadedData(request):
    return base64.b64decode(request["data"]).decode("utf8")


def getPassedConfig(request):
    for k, v in userConfig.items():
        if v["type"] == "Boolean":
            request["config"][k] = True if request["config"][k] == "1" else False
    return request["config"]


def introspection():
    modulesetup = mispattributes
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
