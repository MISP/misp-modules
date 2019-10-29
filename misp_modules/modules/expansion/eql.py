"""
Export module for converting MISP events into Endgame EQL queries
"""
import base64
import csv
import io
import json
import logging

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.1",
    "author": "92 COS DOM",
    "description": "Generates EQL queries from events",
    "module-type": ["expansion"]
}

# Map of MISP fields => ThreatConnect fields
fieldmap = {
#    "domain": "Host",
#    "domain|ip": "Host|Address",
#    "hostname": "hostname",
    "ip-src": "source_address",
    "ip-dst": "destination_address",
#    "ip-src|port": "Address",
#    "ip-dst|port": "Address",
#    "url": "URL",
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
    
    response = []
    fullEql = ""
    for query in queryDict.keys():
        fullEql += "{} where\n".format(query)
        for value in queryDict[query].keys():
            fullEql += "\t{} == \"{}\"\n".format(queryDict[query][value], value)
    response.append({'types': ['comment'], 'categories': ['External analysis'], 'values': fullEql, 'comment': "Event EQL queries"})
    return {'results': response}


def introspection():
    """
    Relay the supported attributes to MISP.
    No Input
    Output
        Dictionary of supported MISP attributes
    """
#    modulesetup = {
#        "responseType": "application/txt",
#        "outputFileExtension": "txt",
#        "userConfig": {},
#        "inputSource": []
#    }
#    return modulesetup
    return mispattributes


def version():
    """
    Relay module version and associated metadata to MISP.
    No Input
    Output
        moduleinfo: metadata output containing all potential configuration values
    """
    #moduleinfo["config"] = moduleconfig
    return moduleinfo
