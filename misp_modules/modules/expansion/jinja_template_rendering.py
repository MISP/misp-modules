#!/usr/bin/env python\

import json

from jinja2.sandbox import SandboxedEnvironment

misperrors = {"error": "Error"}
mispattributes = {"input": ["text"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Sami Mokaddem",
    "description": "Render the template with the data passed",
    "module-type": ["expansion"],
    "name": "Ninja Template Rendering",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

default_template = "- Default template -"


def renderTemplate(data, template=default_template):
    env = SandboxedEnvironment()
    return env.from_string(template).render(data)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("text"):
        data = request["text"]
    else:
        return False
    data = json.loads(data)
    template = data.get("template", default_template)
    templateData = data.get("data", {})
    try:
        rendered = renderTemplate(templateData, template)
    except TypeError:
        rendered = ""

    r = {"results": [{"types": mispattributes["output"], "values": [rendered]}]}
    return r


def introspection():
    return mispattributes


def version():
    return moduleinfo
