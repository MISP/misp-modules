import json

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from ._utils import utils

misperrors = {"error": "Error"}

# config fields that your code expects from the site admin
moduleconfig = {
    "params": {
        "slack_bot_token": {
            "type": "string",
            "description": "The Slack bot token generated when you created the bot account",
        },
        "channel_id": {
            "type": "string",
            "description": "The channel ID you want to post messages to",
        },
        "message_template": {
            "type": "large_string",
            "description": "The template to be used to generate the message to be posted",
            "value": "The **template** will be rendered using *Jinja2*!",
            "jinja_supported": True,
        },
    },
    # Blocking modules break the execution of the current action
    "blocking": False,
    # Indicates whether parts of the data passed to this module should be filtered.
    "support_filters": True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    "expect_misp_core_format": False,
}

# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules, the actual boolean value determines whether we break execution
returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "goodlandsecurity",
    "description": "Simplistic module to send messages to a Slack channel.",
    "module-type": ["action"],
    "name": "Slack",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}


def create_post(request):
    params = request["params"]
    slack_token = params["slack_bot_token"]
    channel_id = params["channel_id"]

    client = WebClient(token=slack_token)

    data = request.get("matchingData", request.get("data", {}))

    if params["message_template"]:
        message = utils.renderTemplate(data, params["message_template"])
    else:
        message = "```\n{}\n```".format(json.dumps(data))

    try:
        client.chat_postMessage(channel=channel_id, text=message)
        return True
    except SlackApiError as e:
        error_message = e.response["error"]
        print(f"Error posting message: {error_message}")
        return False


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    create_post(request)
    return {"data": True}


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
