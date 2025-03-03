"""
Export module for converting MISP events into ThreatConnect Structured Import files. This export data is meant to be used with the "Structured Import" ability of ThreatConnect.

Source: http://kb.threatconnect.com/customer/en/portal/articles/1912599-using-structured-import/
Source: http://kb.threatconnect.com/customer/en/portal/articles/2092925-the-threatconnect-data-model/
"""

import base64
import csv
import io
import json
import logging

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.1",
    "author": "CenturyLink CIRT",
    "description": "Module to export a structured CSV file for uploading to ThreatConnect.",
    "module-type": ["export"],
    "name": "ThreadConnect Export",
    "logo": "threatconnect.png",
    "requirements": ["csv"],
    "features": (
        "The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined"
        " types is then exported in a CSV format recognized by ThreatConnect.\nUsers should then provide, as module"
        " configuration, the source of data they export, because it is required by the output format."
    ),
    "references": ["https://www.threatconnect.com"],
    "input": "MISP Event attributes",
    "output": "ThreatConnect CSV format file",
}

# config fields expected from the MISP administrator
#   Default_Source: The source of the data. Typically this won't be changed from the default
moduleconfig = ["Default_Source"]

# Map of MISP fields => ThreatConnect fields
fieldmap = {
    "domain": "Host",
    "domain|ip": "Host|Address",
    "hostname": "Host",
    "ip-src": "Address",
    "ip-dst": "Address",
    "ip-src|port": "Address",
    "ip-dst|port": "Address",
    "whois-registrant-email": "EmailAddress",
    "email-src": "EmailAddress",
    "email-dst": "EmailAddress",
    "url": "URL",
    "md5": "File",
    "filename|md5": "File",
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
    writer = csv.DictWriter(response, fieldnames=["Type", "Value", "Source", "Description"])
    writer.writeheader()

    # start parsing MISP data
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                logging.debug(
                    "Adding %s to structured CSV export of ThreatConnectExport",
                    attribute["value"],
                )
                if "|" in attribute["type"]:
                    # if the attribute type has multiple values, line it up with the corresponding ThreatConnect values in fieldmap
                    indicators = tuple(attribute["value"].split("|"))
                    tc_types = tuple(fieldmap[attribute["type"]].split("|"))
                    for i, indicator in enumerate(indicators):
                        writer.writerow(
                            {
                                "Type": tc_types[i],
                                "Value": indicator,
                                "Source": config["Default_Source"],
                                "Description": attribute["comment"],
                            }
                        )
                else:
                    writer.writerow(
                        {
                            "Type": fieldmap[attribute["type"]],
                            "Value": attribute["value"],
                            "Source": config["Default_Source"],
                            "Description": attribute["comment"],
                        }
                    )

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
        "outputFileExtension": "csv",
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
    moduleinfo["config"] = moduleconfig
    return moduleinfo
