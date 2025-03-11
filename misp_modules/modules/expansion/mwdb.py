import base64
import io
import json
import sys
import zipfile

from mwdblib import MWDB
from pymisp import PyMISP

# from distutils.util import strtobool


misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment", "malware-sample"], "output": ["link"]}
moduleinfo = {
    "version": "1",
    "author": "Koen Van Impe",
    "description": "Module to push malware samples to a MWDB instance",
    "module-type": ["expansion"],
    "name": "MWDB Submit",
    "logo": "",
    "requirements": [
        "* mwdblib installed (pip install mwdblib) ; * (optional) keys.py file to add tags of events/attributes to MWDB"
        " * (optional) MWDB attribute created for the link back to MISP (defined in mwdb_misp_attribute)"
    ],
    "features": (
        "An expansion module to push malware samples to a MWDB (https://github.com/CERT-Polska/mwdb-core) instance."
        " This module does not push samples to a sandbox. This can be achieved via Karton (connected to the MWDB)."
        " Does: * Upload of attachment or malware sample to MWDB * Tags of events and/or attributes are added to MWDB."
        " * Comment of the MISP attribute is added to MWDB. * A link back to the MISP event is added to MWDB via the"
        " MWDB attribute.  * A link to the MWDB attribute is added as an enrichted attribute to the MISP event."
    ),
    "references": [],
    "input": "Attachment or malware sample",
    "output": "Link attribute that points to the sample at the MWDB instane",
}

moduleconfig = [
    "mwdb_apikey",
    "mwdb_url",
    "mwdb_misp_attribute",
    "mwdb_public",
    "include_tags_event",
    "include_tags_attribute",
]

pymisp_keys_file = "/var/www/MISP/PyMISP/"
mwdb_public_default = True

"""
An expansion module to push malware samples to a MWDB (https://github.com/CERT-Polska/mwdb-core) instance.
This module does not push samples to a sandbox. This can be achieved via Karton (connected to the MWDB)

Does:
- Upload of attachment or malware sample to MWDB
- Tags of events and/or attributes are added to MWDB.
- Comment of the MISP attribute is added to MWDB.
- A link back to the MISP event is added to MWDB via the MWDB attribute.
- A link to the MWDB attribute is added as an enriched attribute to the MISP event.

Requires
- mwdblib installed (pip install mwdblib)
- (optional) keys.py file to add tags of events/attributes to MWDB
- (optional) MWDB "attribute" created for the link back to MISP (defined in mwdb_misp_attribute)
"""


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    try:
        data = request.get("data")
        if "malware-sample" in request:
            # malicious samples are encrypted with zip (password infected) and then base64 encoded
            sample_filename = request.get("malware-sample").split("|", 1)[0]
            data = base64.b64decode(data)
            fl = io.BytesIO(data)
            zf = zipfile.ZipFile(fl)
            sample_hashname = zf.namelist()[0]
            data = zf.read(sample_hashname, b"infected")
            zf.close()
        elif "attachment" in request:
            # All attachments get base64 encoded
            sample_filename = request.get("attachment")
            data = base64.b64decode(data)

        else:
            misperrors["error"] = "No malware sample or attachment supplied"
            return misperrors
    except Exception:
        misperrors["error"] = "Unable to process submited sample data"
        return misperrors

    if (request["config"].get("mwdb_apikey") is None) or (request["config"].get("mwdb_url") is None):
        misperrors["error"] = "Missing MWDB API key or server URL"
        return misperrors

    mwdb_misp_attribute = request["config"].get("mwdb_misp_attribute")
    mwdb_public = request["config"].get("mwdb_public", mwdb_public_default)

    include_tags_event = request["config"].get("include_tags_event")
    include_tags_attribute = request["config"].get("include_tags_attribute")
    misp_event_id = request.get("event_id")
    misp_attribute_uuid = request.get("attribute_uuid")
    misp_attribute_comment = ""
    mwdb_tags = []
    misp_info = ""

    try:
        if include_tags_event:
            sys.path.append(pymisp_keys_file)
            from keys import misp_key, misp_url, misp_verifycert

            misp = PyMISP(misp_url, misp_key, misp_verifycert, False)
            misp_event = misp.get_event(misp_event_id)
            if "Event" in misp_event:
                misp_info = misp_event["Event"]["info"]
                if "Tag" in misp_event["Event"]:
                    tags = misp_event["Event"]["Tag"]
                    for tag in tags:
                        if "misp-galaxy" not in tag["name"]:
                            mwdb_tags.append(tag["name"])
        if include_tags_attribute:
            sys.path.append(pymisp_keys_file)
            from keys import misp_key, misp_url, misp_verifycert

            misp = PyMISP(misp_url, misp_key, misp_verifycert, False)
            misp_attribute = misp.get_attribute(misp_attribute_uuid)
            if "Attribute" in misp_attribute:
                if "Tag" in misp_attribute["Attribute"]:
                    tags = misp_attribute["Attribute"]["Tag"]
                    for tag in tags:
                        if "misp-galaxy" not in tag["name"]:
                            mwdb_tags.append(tag["name"])
                misp_attribute_comment = misp_attribute["Attribute"]["comment"]
    except Exception:
        misperrors["error"] = "Unable to read PyMISP (keys.py) configuration file"
        return misperrors

    try:
        mwdb = MWDB(
            api_key=request["config"].get("mwdb_apikey"),
            api_url=request["config"].get("mwdb_url"),
        )
        if mwdb_misp_attribute and len(mwdb_misp_attribute) > 0:
            metakeys = {mwdb_misp_attribute: misp_event_id}
        else:
            metakeys = False
        file_object = mwdb.upload_file(sample_filename, data, metakeys=metakeys, public=mwdb_public)
        for tag in mwdb_tags:
            file_object.add_tag(tag)
        if len(misp_attribute_comment) < 1:
            misp_attribute_comment = "MISP attribute {}".format(misp_attribute_uuid)
        file_object.add_comment(misp_attribute_comment)
        if len(misp_event) > 0:
            file_object.add_comment("Fetched from event {} - {}".format(misp_event_id, misp_info))
        mwdb_link = request["config"].get("mwdb_url").replace("/api", "/file/") + "{}".format(file_object.md5)
    except Exception:
        misperrors["error"] = "Unable to send sample to MWDB instance"
        return misperrors

    r = {"results": [{"types": "link", "values": mwdb_link, "comment": "Link to MWDB sample"}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
