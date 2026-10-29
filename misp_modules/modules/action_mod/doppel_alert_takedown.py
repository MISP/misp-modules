"""Create a Doppel alert or request takedown through an explicit workflow action."""

import json
import os
import re
from urllib.parse import urlsplit

import requests

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Doppel Alert and Takedown",
    "description": "Create Doppel alerts or explicitly request takedown for an existing alert.",
    "module-type": ["action"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "DOPPEL_API_KEY in the module server environment"],
    "features": "Actions use the Doppel V1 API. Existing actioned or resolved alerts are not actioned again.",
    "references": ["https://doppel.readme.io/docs/request-takedown"],
    "input": "Explicit entity URL or alert ID and action parameters.",
    "output": "Alert ID, workflow state, link and whether a request was performed.",
}
moduleconfig = {
    "params": {
        "action": {"type": "string", "value": "create_alert", "description": "create_alert or request_takedown"},
        "entity": {"type": "string", "description": "HTTP(S) URL; exactly one of entity or alert_id for takedown"},
        "alert_id": {"type": "string", "description": "Existing Doppel alert ID, such as ACM-1234"},
        "comment": {"type": "large_string", "description": "Optional rationale, sent with a takedown request"},
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": False,
}
returns = "data"
API = "https://api.doppel.com/v1/alert"


class ActionError(ValueError):
    """A diagnostic that does not expose credentials."""


def _request(method, headers, **kwargs):
    try:
        response = requests.request(
            method, API, headers=headers, timeout=(5, 30), verify=True, allow_redirects=False, **kwargs
        )
    except requests.RequestException:
        raise ActionError("Doppel request failed or timed out; check the alert before repeating the action.") from None
    if response.status_code not in (200, 201):
        raise ActionError(f"Doppel returned HTTP {response.status_code}; check the alert before retrying.")
    try:
        data = response.json()
    except ValueError:
        raise ActionError("Doppel returned invalid JSON; check the alert before retrying.") from None
    if not isinstance(data, dict) or not isinstance(data.get("id"), str) or not data["id"]:
        raise ActionError("Doppel did not return an alert acknowledgement; check the service before retrying.")
    return data


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        params = request.get("params") if isinstance(request, dict) else None
        if not isinstance(params, dict):
            raise ActionError("Workflow params are required.")
        action = params.get("action", "create_alert")
        entity, alert_id = params.get("entity") or "", params.get("alert_id") or ""
        comment = params.get("comment") or ""
        if action not in ("create_alert", "request_takedown"):
            raise ActionError("action must be create_alert or request_takedown.")
        if not all(isinstance(value, str) for value in (entity, alert_id, comment)):
            raise ActionError("entity, alert_id and comment must be strings.")
        if entity:
            parsed = urlsplit(entity)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or any(ord(c) <= 32 for c in entity)
            ):
                raise ActionError("entity must be an HTTP(S) URL without embedded credentials.")
            parsed.port
        if alert_id and not re.fullmatch(r"[A-Za-z0-9]+-[0-9]+", alert_id):
            raise ActionError("Invalid Doppel alert ID.")
        if bool(entity) == bool(alert_id) or (action == "create_alert" and not entity):
            raise ActionError("Supply entity for creation, or exactly one of entity and alert_id for takedown.")
        if len(comment) > 10000:
            raise ActionError("comment must be at most 10000 characters.")
        api_key = os.getenv("DOPPEL_API_KEY", "")
        if not api_key:
            raise ActionError("Configure DOPPEL_API_KEY in the module server environment.")
        headers = {"x-api-key": api_key, "Accept": "application/json"}
        for environment, header in [
            ("DOPPEL_USER_API_KEY", "x-user-api-key"),
            ("DOPPEL_ORGANIZATION_CODE", "x-organization-code"),
        ]:
            if os.getenv(environment):
                headers[header] = os.environ[environment]
        performed = True
        if action == "create_alert":
            data = _request("POST", headers, json={"entity": entity})
        else:
            selector = {"id": alert_id} if alert_id else {"entity": entity}
            data = _request("GET", headers, params=selector)
            if data.get("queue_state") in ("actioned", "taken_down"):
                performed = False
            else:
                body = {"queue_state": "actioned"}
                if comment:
                    body["comment"] = comment
                data = _request("PUT", headers, params=selector, json=body)
                if data.get("queue_state") != "actioned":
                    raise ActionError(
                        "Doppel did not acknowledge the takedown request; check the alert before retrying."
                    )
        return {
            "data": {
                "action": action,
                "alert_id": data["id"],
                "queue_state": data.get("queue_state"),
                "link": "https://app.doppel.com/alerts/" + data["id"],
                "request_performed": performed,
            }
        }
    except ActionError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"error": "Invalid workflow parameters or Doppel response."}


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
