"""Send workflow messages through signal-cli-rest-api."""

import json
import re
from urllib.parse import urlsplit

import requests
from jinja2 import TemplateError

from ._utils import utils

misperrors = {"error": "Error"}

moduleconfig = {
    "params": {
        "signal_api_url": {
            "type": "string",
            "description": "Base URL of your signal-cli-rest-api service, including any proxy path prefix",
            "value": "http://localhost:8080",
        },
        "sender_number": {
            "type": "string",
            "description": "Registered or linked Signal account number in international format, e.g. +33123456789",
        },
        "recipients": {
            "type": "string",
            "description": "Comma-separated international phone numbers or signal-cli-rest-api group IDs (group.…)",
        },
        "message_template": {
            "type": "large_string",
            "description": "Jinja2 message template; leave empty to send the workflow data as JSON",
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
    "description": "Send a message to Signal recipients or a group through signal-cli-rest-api.",
    "module-type": ["action"],
    "name": "Signal",
    "logo": "",
    "requirements": ["requests", "A configured signal-cli-rest-api service with a registered or linked account"],
    "features": (
        "Renders Jinja2 templates using matchingData when present, otherwise data, with a JSON fallback."
        " Sends plain-text messages through POST /v2/send. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/signal.md)."
    ),
    "references": ["https://github.com/bbernhard/signal-cli-rest-api"],
    "input": "Workflow data or matchingData, and an optional Jinja2 message template.",
    "output": "Boolean success; errors indicate an unsuccessful or unacknowledged send.",
}


def create_post(request):
    params = request["params"]
    base_url = params["signal_api_url"]
    if not isinstance(base_url, str) or any(char.isspace() or ord(char) < 32 for char in base_url):
        raise ValueError("Invalid Signal API URL")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port == 0
    ):
        raise ValueError("Invalid Signal API URL")

    number = params["sender_number"]
    if not isinstance(number, str) or not re.fullmatch(r"\+[1-9][0-9]{1,14}", number):
        raise ValueError("Invalid Signal sender number")
    recipients = params["recipients"]
    if not isinstance(recipients, str):
        raise ValueError("Invalid Signal recipients")
    recipients = [recipient.strip() for recipient in recipients.split(",")]
    if not recipients or any(
        not re.fullmatch(r"\+[1-9][0-9]{1,14}|group\.[A-Za-z0-9+/=_-]+", recipient) for recipient in recipients
    ):
        raise ValueError("Invalid Signal recipients")

    data = request["matchingData"] if "matchingData" in request else request["data"]
    template = params.get("message_template", "")
    if not isinstance(template, str):
        raise ValueError("Invalid message template")
    message = utils.renderTemplate(data, template) if template else "```\n{}\n```".format(json.dumps(data))
    if not message.strip():
        raise ValueError("Empty Signal message")

    response = requests.post(
        f"{base_url.rstrip('/')}/v2/send",
        json={"number": number, "recipients": recipients, "message": message},
        timeout=30,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 201:
        return False
    acknowledgement = response.json()
    timestamp = acknowledgement.get("timestamp") if isinstance(acknowledgement, dict) else None
    return (
        not isinstance(timestamp, bool)
        and isinstance(timestamp, (int, str))
        and str(timestamp).isascii()
        and str(timestamp).isdigit()
        and int(timestamp) > 0
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
        return {"data": False, "error": "Signal request failed; check the API service, sender account and recipients."}
    except (KeyError, TypeError, ValueError, TemplateError):
        return {"data": False, "error": "Invalid Signal configuration, workflow data, template or API response."}
    if not success:
        return {"data": False, "error": "Signal message was not acknowledged by the API service."}
    return {"data": True}


def introspection():
    return {"config": moduleconfig}


def version():
    return {**moduleinfo, "config": moduleconfig}
