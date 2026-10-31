"""Upload a typed MISP indicator snapshot through the Wazuh server API."""

import hashlib
import json
import os
import re
from urllib.parse import urlsplit

import requests

from misp_modules.lib.wazuh_cdb import boolean, build, warnings

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Wazuh CDB Publish",
    "description": "Upload MISP event and object indicators to an explicitly named Wazuh CDB source list.",
    "module-type": ["action"],
    "logo": "",
    "requirements": [
        "requests",
        "Wazuh server API credentials with lists:update and lists:delete permissions",
        "Optional reload: manager:read/manager:restart or cluster:read/cluster:restart permissions",
    ],
    "features": (
        "Uploads one typed, deduplicated list of to_ids indicators using PUT /lists/files/{filename}. Credentials"
        " come from the module server environment. Supports a credential-free dry run and explicit overwrite;"
        " overwrite replaces the entire list with the supplied snapshot. Checks the Wazuh acknowledgement,"
        " refuses empty lists and optionally requests an analysisd reload on the manager or cluster without a full"
        " manager restart. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/wazuh_cdb_publish.md)."
    ),
    "references": [
        "https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Lists",
        "https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Manager",
        "https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Cluster",
        "https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html",
    ],
    "input": "Selected MISP events and object attributes in workflow data.",
    "output": "Upload and reload status, selected filename, indicator counts, content SHA-256 and activation notice.",
}
moduleconfig = {
    "params": {
        "filename": {"type": "string", "description": "Required: dedicated list basename, e.g. misp-ipv4"},
        "indicator_type": {
            "type": "string",
            "description": "ipv4, ipv6, domain, md5, sha1, sha256 or sha512",
            "value": "ipv4",
        },
        "overwrite": {
            "type": "string",
            "description": "true replaces the complete existing file with this snapshot",
            "value": "false",
        },
        "dry_run": {
            "type": "string",
            "description": "true previews the upload without network access",
            "value": "false",
        },
        "reload": {
            "type": "string",
            "description": (
                "none (upload only), manager (local node) or cluster (all nodes): reload analysisd after upload"
            ),
            "value": "none",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


class PublishError(Exception):
    """A sanitized error safe to include in a workflow result."""


def _connection():
    origin = os.getenv("WAZUH_URL", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 or ord(char) == 127 for char in origin)
    ):
        raise ValueError("Configure WAZUH_URL as an HTTPS API origin, e.g. https://wazuh.example:55000.")
    parsed.port
    token = os.getenv("WAZUH_API_TOKEN", "")
    username, password = os.getenv("WAZUH_USERNAME", ""), os.getenv("WAZUH_PASSWORD", "")
    if token:
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise ValueError("WAZUH_API_TOKEN must be a JWT.")
    elif not username or not password or ":" in username:
        raise ValueError("Configure WAZUH_API_TOKEN or WAZUH_USERNAME and WAZUH_PASSWORD on the module server.")
    return origin.rstrip("/"), token, (username, password), os.getenv("WAZUH_CA_BUNDLE") or True


def _request(session, method, url, verify, **kwargs):
    try:
        response = session.request(method, url, timeout=(5, 30), verify=verify, allow_redirects=False, **kwargs)
    except (requests.RequestException, OSError, UnicodeError):
        raise PublishError(
            f"{method} failed. Check Wazuh before retrying; the request outcome may be unknown."
        ) from None
    if response.status_code != 200:
        raise PublishError(f"{method}: Wazuh HTTP {response.status_code}. Check Wazuh before retrying.")
    return response


def _authenticate(session, origin, credentials, verify):
    response = _request(
        session, "POST", origin + "/security/user/authenticate", verify, params={"raw": "true"}, auth=credentials
    )
    token = response.text.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
        raise PublishError("Authentication returned an invalid token; no list uploaded.")
    return token


def _check_acknowledgement(response, filename):
    try:
        body = response.json()
    except ValueError:
        raise PublishError("Invalid JSON acknowledgement; upload outcome may be unknown.") from None
    data = body.get("data") if isinstance(body, dict) else None
    if (
        not isinstance(body, dict)
        or type(body.get("error")) is not int
        or body["error"] != 0
        or not isinstance(data, dict)
        or type(data.get("total_failed_items")) is not int
        or data["total_failed_items"] != 0
        or data.get("failed_items") != []
        or type(data.get("total_affected_items")) is not int
        or data["total_affected_items"] != 1
        or data.get("affected_items") != [f"etc/lists/{filename}"]
    ):
        raise PublishError("Wazuh did not acknowledge the selected list upload; check Wazuh before retrying.")


def _check_reload_acknowledgement(response, mode):
    try:
        body = response.json()
    except ValueError:
        raise PublishError("Invalid JSON reload acknowledgement; check Wazuh before retrying.") from None
    data = body.get("data") if isinstance(body, dict) else None
    if (
        not isinstance(body, dict)
        or type(body.get("error")) is not int
        or body["error"] != 0
        or not isinstance(data, dict)
        or type(data.get("total_failed_items")) is not int
        or data["total_failed_items"] != 0
        or data.get("failed_items") != []
    ):
        raise PublishError("Wazuh did not acknowledge the complete reload; some nodes may still require a reload.")
    items = data.get("affected_items")
    if (
        not isinstance(items, list)
        or not items
        or type(data.get("total_affected_items")) is not int
        or data["total_affected_items"] != len(items)
        or (mode == "manager" and len(items) != 1)
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("msg"), str)
            or not item["msg"]
            or item["msg"] == "Failed to send the ruleset reload request."
            for item in items
        )
    ):
        raise PublishError("Invalid or unsuccessful per-node reload acknowledgement; check Wazuh before retrying.")
    names = [item["name"] for item in items]
    if len(set(names)) != len(names):
        raise PublishError("Duplicate nodes in reload acknowledgement; check Wazuh before retrying.")
    # Successful master-node reloads can return warning text instead of the usual
    # success message. Flag those nodes without echoing arbitrary remote messages.
    warning_nodes = [item["name"] for item in items if item["msg"] != "Ruleset reload request sent successfully."]
    return names, warning_nodes


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError("Workflow filters/extracted data are unsupported; supply selected events in data.")
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params must be an object.")
        filename = params.get("filename")
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", filename):
            raise ValueError("filename must be a basename of 1-128 ASCII letters, digits, underscores or hyphens.")
        overwrite = boolean(params.get("overwrite"), "overwrite")
        dry_run = boolean(params.get("dry_run"), "dry_run")
        reload_mode = params.get("reload")
        if reload_mode is None or reload_mode == "":
            reload_mode = "none"
        if not isinstance(reload_mode, str) or reload_mode not in ("none", "manager", "cluster"):
            raise ValueError("reload must be none, manager or cluster.")
        output, summary, sources = build(request.get("data"), params)
    except (ValueError, TypeError) as exc:
        return {"error": f"Wazuh CDB publish: {exc}"}
    summary.update(
        success=False,
        filename=filename,
        overwrite=overwrite,
        dry_run=dry_run,
        reload=reload_mode,
        status="not_uploaded",
        activation="pending",
        sha256=hashlib.sha256(output).hexdigest(),
        bytes=len(output),
    )
    result = {"result_key": "wazuh_cdb_publish", "data": summary, "warnings": warnings(summary), "sources": sources}
    if dry_run:
        summary.update(success=True, status="planned", content=output.decode("ascii"))
        return result
    try:
        try:
            origin, token, credentials, verify = _connection()
        except ValueError:
            raise PublishError(
                "Configure an HTTPS WAZUH_URL and WAZUH_API_TOKEN or WAZUH_USERNAME/WAZUH_PASSWORD on the module"
                " server."
            ) from None
        with requests.Session() as session:
            if not token:
                token = _authenticate(session, origin, credentials, verify)
            summary["status"] = "unknown"
            response = _request(
                session,
                "PUT",
                origin + "/lists/files/" + filename,
                verify,
                params={"overwrite": str(overwrite).lower()},
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream"},
                data=output,
            )
            _check_acknowledgement(response, filename)
            summary["status"] = "uploaded"
            if reload_mode != "none":
                summary["activation"] = "unknown"
                response = _request(
                    session,
                    "PUT",
                    f"{origin}/{reload_mode}/analysisd/reload",
                    verify,
                    headers={"Authorization": "Bearer " + token},
                )
                summary["reload_nodes"], summary["reload_warning_nodes"] = _check_reload_acknowledgement(
                    response, reload_mode
                )
                summary["activation"] = "reload_requested"
    except PublishError as exc:
        prefix = "Upload succeeded, but analysisd reload failed: " if summary["status"] == "uploaded" else ""
        result["error"] = f"Wazuh CDB publish: {prefix}{exc}"
        return result
    summary.update(success=True, status="uploaded")
    result["warnings"] = warnings(summary)
    return result


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
