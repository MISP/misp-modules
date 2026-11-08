"""Export MISP event to VirusTotal Graph."""

import base64
import json

import requests
from vt_graph_api import errors as vt_errors

from misp_modules.lib.vt_graph_parser.errors import GraphImportError
from misp_modules.lib.vt_graph_parser.helpers.parsers import GRAPH_ID_PATTERN, MISP_INPUT_ATTR, boolean
from misp_modules.lib.vt_graph_parser.importers.pymisp_response import from_pymisp_response

moduleinfo = {
    "version": "0.2",
    "author": "VirusTotal",
    "description": "This module is used to create a VirusTotal Graph from a MISP event.",
    "module-type": ["export"],
    "name": "VirusTotal Graph Export",
    "logo": "virustotal.png",
    "requirements": ["vt-graph-api, the official VirusTotal Graph SDK (tested with 2.2.0)"],
    "features": (
        "The module takes the MISP event as input and queries the VirusTotal Graph API to create a new graph out of the"
        " event, or update an existing graph linked in the event. Supports flat and wrapped events, object attributes"
        " and filename/hash composites. Boolean configuration accepts true/false strings.\n\nReturns graph links as a"
        " text file. See https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/vt_graph.md for API v3"
        " behavior, visibility and quota details."
    ),
    "references": [
        "https://docs.virustotal.com/reference/create-graphs",
        "https://docs.virustotal.com/reference/graphs-update",
        "https://docs.virustotal.com/reference/graph-object",
        "https://github.com/VirusTotal/vt-graph-api",
    ],
    "input": "A MISP event.",
    "output": "Link of the VirusTotal Graph created for the event.",
}
mispattributes = {"input": MISP_INPUT_ATTR}
moduleconfig = [
    "vt_api_key",
    "fetch_information",
    "private",
    "fetch_vt_enterprise",
    "expand_one_level",
    "user_editors",
    "user_viewers",
    "group_editors",
    "group_viewers",
]


def _collaborators(value, name):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise GraphImportError(f"{name} must be a comma-separated string.")
    return list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


def handler(q=False):
    """Export the selected MISP events using the official API v3 Graph SDK."""
    if not q:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "The export request must be valid JSON."}
    if not isinstance(request, dict):
        return {"error": "The export request must be an object."}
    config = request.get("config")
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("vt_api_key"), str)
        or not config["vt_api_key"].strip()
    ):
        return {"error": "A VirusTotal API key is required for this module."}

    try:
        options = {
            name: boolean(config.get(name), name)
            for name in (
                "fetch_information",
                "private",
                "fetch_vt_enterprise",
                "expand_one_level",
            )
        }
        collaborators = {
            name: _collaborators(config.get(name), name)
            for name in (
                "user_editors",
                "user_viewers",
                "group_editors",
                "group_viewers",
            )
        }
        graphs = from_pymisp_response(
            request,
            config["vt_api_key"],
            fetch_information=options["fetch_information"],
            private=options["private"],
            fetch_vt_enterprise=options["fetch_vt_enterprise"],
            expand_node_one_level=options["expand_one_level"],
            **collaborators,
        )
        links = []
        for graph in graphs:
            graph.save_graph()
            if not isinstance(graph.graph_id, str) or not GRAPH_ID_PATTERN.fullmatch(graph.graph_id):
                raise vt_errors.SaveGraphError()
            links.append(graph.get_ui_link())
    except GraphImportError as error:
        return {"error": str(error)}
    except (
        requests.RequestException,
        vt_errors.SaveGraphError,
        vt_errors.LoadError,
        vt_errors.InvalidJSONError,
        vt_errors.CollaboratorNotFoundError,
        vt_errors.NodeNotFoundError,
        vt_errors.NodeNotSupportedTypeError,
        vt_errors.NodeNotSupportedExpansionError,
        vt_errors.SameNodeError,
        vt_errors.MaximumConnectionRetriesError,
        ValueError,
        KeyError,
        TypeError,
    ):
        # The SDK may include raw response bodies or request details in errors.
        # A save or collaborator update can fail after a graph has been created.
        return {
            "error": (
                "VirusTotal Graph export failed. Check your API access, quota and existing graphs before retrying;"
                " one or more graphs may already have been saved."
            )
        }

    file_data = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    return {"response": [], "data": file_data}


def introspection():
    modulesetup = {
        "responseType": "application/txt",
        "outputFileExtension": "txt",
        "userConfig": {},
        "inputSource": [],
    }
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
