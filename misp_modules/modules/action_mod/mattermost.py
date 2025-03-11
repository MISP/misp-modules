import json

from mattermostdriver import Driver
from pymisp.tools._psl_faup import PSLFaup as Faup

from ._utils import utils

misperrors = {"error": "Error"}

# config fields that your code expects from the site admin
moduleconfig = {
    "params": {
        "mattermost_hostname": {
            "type": "string",
            "description": "The Mattermost domain or URL",
            "value": "example.mattermost.com",
        },
        "bot_access_token": {
            "type": "string",
            "description": "Access token generated when you created the bot account",
        },
        "channel_id": {
            "type": "string",
            "description": "The channel you added the bot to",
        },
        "message_template": {
            "type": "large_string",
            "description": "The template to be used to generate the message to be posted",
            "value": "The **template** will be rendered using *Jinja2*!",
            "jinja_supported": True,
        },
    },
    # Blocking modules break the exection of the current of action
    "blocking": False,
    # Indicates whether parts of the data passed to this module should be filtered. Filtered data can be found under the `filteredItems` key
    "support_filters": True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    "expect_misp_core_format": False,
}


# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules the actual boolean value determines whether we break execution
returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "Sami Mokaddem",
    "description": "Simplistic module to send message to a Mattermost channel.",
    "module-type": ["action"],
    "name": "Mattermost",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

f = Faup()


def createPost(request):
    params = request["params"]
    f.decode(params["mattermost_hostname"])
    parsedURL = f.get()
    mm = Driver(
        {
            "url": parsedURL["host"],
            "token": params["bot_access_token"],
            "scheme": parsedURL["scheme"] if parsedURL["scheme"] is not None else "https",
            "basepath": "/api/v4",
            "port": int(parsedURL["port"]) if parsedURL["port"] is not None else 443,
        }
    )
    mm.login()

    data = {}
    if "matchingData" in request:
        data = request["matchingData"]
    else:
        data = request["data"]

    if params["message_template"]:
        message = utils.renderTemplate(data, params["message_template"])
    else:
        message = "```\n{}\n```".format(json.dumps(data))

    mm.posts.create_post(options={"channel_id": params["channel_id"], "message": message})
    return True


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    createPost(request)
    r = {"data": True}
    return r


def introspection():
    modulesetup = {}
    try:
        modulesetup["config"] = moduleconfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
