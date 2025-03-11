"""
Export module for converting MISP events into Endgame EQL queries
"""

import base64
import io
import json
import logging

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.1",
    "author": "92 COS DOM",
    "description": "Export MISP event in Event Query Language",
    "module-type": ["export"],
    "name": "EQL Query Export",
    "logo": "eql.png",
    "requirements": [],
    "features": "This module produces EQL queries for all relevant attributes in a MISP event.",
    "references": ["https://eql.readthedocs.io/en/latest/"],
    "input": "MISP Event attributes",
    "output": "Text file containing one or more EQL queries",
}

# Map of MISP fields => Endgame fields
fieldmap = {
    "ip-src": "source_address",
    "ip-dst": "destination_address",
    "filename": "file_name",
}

# Describe what events have what fields
event_types = {
    "source_address": "network",
    "destination_address": "network",
    "file_name": "file",
}

# combine all the MISP fields from fieldmap into one big list
mispattributes = {"input": list(fieldmap.keys())}


def handler(q=False):
    """
    Convert a MISP query into a CSV file matching the ThreatConnect Structured Import file format.
    Input
        q: Query dictionary
    """
    if q is False or not q:
        return False

    # Check if we were given a configuration
    request = json.loads(q)
    config = request.get("config", {"Default_Source": ""})
    logging.info("Setting config to: %s", config)

    response = io.StringIO()

    # start parsing MISP data
    queryDict = {}
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                logging.debug("Adding %s to EQL query", attribute["value"])
                event_type = event_types[fieldmap[attribute["type"]]]
                if event_type not in queryDict.keys():
                    queryDict[event_type] = {}
                queryDict[event_type][attribute["value"]] = fieldmap[attribute["type"]]
    i = 0
    for query in queryDict.keys():
        response.write("{} where\n".format(query))
        for value in queryDict[query].keys():
            if i != 0:
                response.write(" or\n")
            response.write('\t{} == "{}"'.format(queryDict[query][value], value))
            i += 1

    return {
        "response": [],
        "data": str(base64.b64encode(bytes(response.getvalue(), "utf-8")), "utf-8"),
    }


def introspection():
    """
    Relay the supported attributes to MISP.
    No Input
    Output
        Dictionary of supported MISP attributes
    """
    modulesetup = {
        "responseType": "application/txt",
        "outputFileExtension": "txt",
        "userConfig": {},
        "inputSource": [],
    }
    return modulesetup


def version():
    """
    Relay module version and associated metadata to MISP.
    No Input
    Output
        moduleinfo: metadata output containing all potential configuration values
    """
    return moduleinfo
