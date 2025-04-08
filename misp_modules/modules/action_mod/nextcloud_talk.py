import json
import requests


from ._utils import utils

misperrors = {"error": "Error"}

# config fields that your code expects from the site admin
moduleconfig = {
    "params": {
        "nextcloud_baseurl": {
            "type": "string",
            "description": "The Nexctloud domain or URL",
            "value": "https://example.nextcloud.org:443",
        },
        "nextcloud_app_uuid_login": {
            "type": "string",
            "description": "The nextcloud username",
        },
        "app_access_token": {
            "type": "string",
            "description": "The nextcloud application token",
        },
        "nextcloud_conversation_token": {
            "type": "string",
            "description": "The token of the conversation the message should be sent to",
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
    "author": "Jeroen Pinoy",
    "description": "Simplistic module to send a message to a Nextcloud talk conversation.",
    "module-type": ["action"],
    "name": "Nextcloud talk",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}


def createPost(request):
    params = request["params"]
    nextcloud_baseurl = params["nextcloud_baseurl"]
    nextcloud_conversation_token = params["nextcloud_conversation_token"]

    # Construct the API endpoint
    endpoint = f"{nextcloud_baseurl}/ocs/v2.php/apps/spreed/api/v1/chat/{nextcloud_conversation_token}"

    # Headers required for the API call
    headers = {
        'OCS-APIRequest': 'true',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    data = {}
    if "matchingData" in request:
        data = request["matchingData"]
    else:
        data = request["data"]

    if params["message_template"]:
        message = utils.renderTemplate(data, params["message_template"])
    else:
        message = "```\n{}\n```".format(json.dumps(data))

    # Message data
    message_data = {
        'message': message
    }

    try:
        # Make POST request to send message
        response = requests.post(
            endpoint,
            headers=headers,
            auth=(params["nextcloud_app_uuid_login"], params["app_access_token"]),
            json=message_data
        )
        return True
    except requests.exceptions.RequestException as e:
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
