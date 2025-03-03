"""
Export module for coverting MISP events into ThreatStream Structured Import files. Based of work by the CenturyLink CIRT.
Source: https://github.com/MISP/misp-modules/blob/master/misp_modules/modules/export_mod/threat_connect_export.py
"""

import base64
import csv
import io
import json
import logging

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "1.0",
    "author": "Robert Nixon, based off of the ThreatConnect MISP Module written by the CenturyLink CIRT",
    "description": "Module to export a structured CSV file for uploading to threatStream.",
    "module-type": ["export"],
    "name": "ThreatStream Export",
    "logo": "threatstream.png",
    "requirements": ["csv"],
    "features": (
        "The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined"
        " types is then exported in a CSV format recognized by ThreatStream."
    ),
    "references": [
        "https://www.anomali.com/platform/threatstream",
        "https://github.com/threatstream",
    ],
    "input": "MISP Event attributes",
    "output": "ThreatStream CSV format file",
}


moduleconfig = []


# Map of MISP fields => ThreatStream itypes, you can modify this to your liking
fieldmap = {
    "domain": "mal_domain",
    "hostname": "mal_domain",
    "ip-src": "mal_ip",
    "ip-dst": "mal_ip",
    "email-src": "phish_email",
    "url": "mal_url",
    "md5": "mal_md5",
}

# combine all the MISP fields from fieldmap into one big list
mispattributes = {"input": list(fieldmap.keys())}


def handler(q=False):
    """
    Convert a MISP query into a CSV file matching the ThreatStream Structured Import file format.
    Input
        q: Query dictionary
    """
    if q is False or not q:
        return False

    request = json.loads(q)

    response = io.StringIO()
    writer = csv.DictWriter(response, fieldnames=["value", "itype", "tags"])
    writer.writeheader()

    # start parsing MISP data
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                logging.debug(
                    "Adding %s to structured CSV export of ThreatStream Export",
                    attribute["value"],
                )
                if "|" in attribute["type"]:
                    # if the attribute type has multiple values, line it up with the corresponding ThreatStream values in fieldmap
                    indicators = tuple(attribute["value"].split("|"))
                    ts_types = tuple(fieldmap[attribute["type"]].split("|"))
                    for i, indicator in enumerate(indicators):
                        writer.writerow(
                            {
                                "value": indicator,
                                "itype": ts_types[i],
                                "tags": attribute["comment"],
                            }
                        )
                else:
                    writer.writerow(
                        {
                            "itype": fieldmap[attribute["type"]],
                            "value": attribute["value"],
                            "tags": attribute["comment"],
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
