"""
Export module for converting MISP events into Endgame EQL queries
"""
import json
import logging

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.1",
    "author": "92 COS DOM",
    "description": "Generates EQL queries from events",
    "module-type": ["expansion"]
}

# Map of MISP fields => Endgame fields
fieldmap = {
    "ip-src": "source_address",
    "ip-dst": "destination_address",
    "filename": "file_name"
}

# Describe what events have what fields
event_types = {
    "source_address": "network",
    "destination_address": "network",
    "file_name": "file"
}

# combine all the MISP fields from fieldmap into one big list
mispattributes = {
    "input": list(fieldmap.keys())
}


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

    for supportedType in fieldmap.keys():
        if request.get(supportedType):
            attrType = supportedType

    if attrType:
        eqlType = fieldmap[attrType]
        event_type = event_types[eqlType]
        fullEql = "{} where {} == \"{}\"".format(event_type, eqlType, request[attrType])
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    response = []
    response.append({'types': ['comment'], 'categories': ['External analysis'], 'values': fullEql, 'comment': "Event EQL queries"})
    return {'results': response}


def introspection():
    """
    Relay the supported attributes to MISP.
    No Input
    Output
        Dictionary of supported MISP attributes
    """
    return mispattributes


def version():
    """
    Relay module version and associated metadata to MISP.
    No Input
    Output
        moduleinfo: metadata output containing all potential configuration values
    """
    return moduleinfo
