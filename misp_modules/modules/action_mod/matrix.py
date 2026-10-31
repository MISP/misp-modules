"""Send workflow messages to an unencrypted Matrix room."""

import json
from urllib.parse import quote, urlsplit
from uuid import uuid4

import requests
from jinja2 import TemplateError

from ._utils import utils

misperrors = {"error": "Error"}

moduleconfig = {
    "params": {
        "matrix_homeserver": {
            "type": "string",
            "description": "The Matrix homeserver base URL, including scheme and optional path prefix",
            "value": "https://matrix.example.org",
        },
        "bot_access_token": {
            "type": "string",
            "description": "Access token for a Matrix bot that has joined the room",
        },
        "room_id": {
            "type": "string",
            "description": "The unencrypted room ID (starting with !), not a room alias",
        },
        "message_template": {
            "type": "large_string",
            "description": "Jinja2 template for the plain-text message; leave empty to send the workflow data as JSON",
            "value": "MISP event: {{ Event.info }}",
            "jinja_supported": True,
        },
    },
    "blocking": False,
    "support_filters": True,
    "expect_misp_core_format": False,
}

returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": "Send a message to an unencrypted Matrix room.",
    "module-type": ["action"],
    "name": "Matrix",
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Renders Jinja2 templates using matchingData when present, otherwise data, with a JSON fallback."
        " Sends plain-text m.room.message events using a bot access token. The bot must already be a room member"
        " with permission to send messages. End-to-end encrypted rooms and HTML/Markdown formatting are unsupported."
        " See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/matrix.md)."
    ),
    "references": ["https://spec.matrix.org/latest/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid"],
    "input": "Workflow data or matchingData, and an optional Jinja2 message template.",
    "output": "Boolean success; errors indicate an unsuccessful or unacknowledged send.",
}


def create_post(request):
    params = request["params"]
    for name in ("matrix_homeserver", "bot_access_token", "room_id"):
        value = params[name]
        if not isinstance(value, str) or not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid Matrix configuration")

    homeserver = params["matrix_homeserver"].rstrip("/")
    parsed = urlsplit(homeserver)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or " " in homeserver
        or parsed.port == 0
        or not params["room_id"].startswith("!")
        or len(params["room_id"]) == 1
    ):
        raise ValueError("Invalid Matrix configuration")

    data = request["matchingData"] if "matchingData" in request else request["data"]
    template = params.get("message_template", "")
    if not isinstance(template, str):
        raise ValueError("Invalid message template")
    message = utils.renderTemplate(data, template) if template else "```\n{}\n```".format(json.dumps(data))

    room_id = quote(params["room_id"], safe="")
    # A fresh transaction ID distinguishes separate workflow invocations.
    endpoint = f"{homeserver}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{uuid4().hex}"
    response = requests.put(
        endpoint,
        headers={"Authorization": f"Bearer {params['bot_access_token']}"},
        json={"msgtype": "m.text", "body": message},
        timeout=30,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        return False
    acknowledgement = response.json()
    return (
        isinstance(acknowledgement, dict)
        and isinstance(acknowledgement.get("event_id"), str)
        and bool(acknowledgement["event_id"])
    )


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("params"), dict):
            raise ValueError("Invalid request")
        success = create_post(request)
    except requests.RequestException:
        # Provider errors and request URLs may contain sensitive data.
        return {"data": False, "error": "Matrix request failed; check the homeserver, bot token and room permissions."}
    except (KeyError, TypeError, ValueError, TemplateError):
        return {"data": False, "error": "Invalid Matrix configuration, workflow data, template or homeserver response."}
    if not success:
        return {"data": False, "error": "Matrix message was not acknowledged by the homeserver."}
    return {"data": True}


def introspection():
    return {"config": moduleconfig}


def version():
    return {**moduleinfo, "config": moduleconfig}
