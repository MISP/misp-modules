import base64
import io
import logging
import sys
import zipfile
from typing import Optional

import clamd
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("clamav")
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
sh.setFormatter(fmt)
log.addHandler(sh)

moduleinfo = {
    "version": "0.1",
    "author": "Jakub Onderka",
    "description": "Submit file to ClamAV",
    "module-type": ["expansion"],
    "name": "ClaamAV",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}
moduleconfig = ["connection"]
mispattributes = {"input": ["attachment", "malware-sample"], "format": "misp_standard"}


def create_response(original_attribute: dict, software: str, signature: Optional[str] = None) -> dict:
    misp_event = MISPEvent()
    if signature:
        misp_event.add_attribute(**original_attribute)

        av_signature_object = MISPObject("av-signature")
        av_signature_object.add_attribute("signature", signature)
        av_signature_object.add_attribute("software", software)
        av_signature_object.add_reference(original_attribute["uuid"], "belongs-to")
        misp_event.add_object(av_signature_object)

    event = misp_event.to_dict()
    results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
    return {"results": results}


def connect_to_clamav(connection_string: str) -> clamd.ClamdNetworkSocket:
    if connection_string.startswith("unix://"):
        return clamd.ClamdUnixSocket(connection_string.replace("unix://", ""))
    elif ":" in connection_string:
        host, port = connection_string.split(":")
        return clamd.ClamdNetworkSocket(host, int(port))
    else:
        raise Exception(
            "ClamAV connection string is invalid. It must be unix socket path with 'unix://' prefix or IP:PORT."
        )


def dict_handler(request: dict):
    connection_string: str = request["config"].get("connection")
    if not connection_string:
        return {"error": "No ClamAV connection string provided"}

    attribute = request.get("attribute")
    if not attribute:
        return {"error": "No attribute provided"}

    if not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}

    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Invalid attribute type provided, expected 'malware-sample' or 'attachment'"}

    attribute_data = attribute.get("data")
    if not attribute_data:
        return {"error": "No attribute data provided"}

    try:
        clamav = connect_to_clamav(connection_string)
        software_version = clamav.version()
    except Exception:
        logging.exception("Could not connect to ClamAV")
        return {"error": "Could not connect to ClamAV"}

    try:
        data = base64.b64decode(attribute_data, validate=True)
    except Exception:
        logging.exception("Provided data is not valid base64 encoded string")
        return {"error": "Provided data is not valid base64 encoded string"}

    if attribute["type"] == "malware-sample":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zipf:
                data = zipf.read(zipf.namelist()[0], pwd=b"infected")
        except Exception:
            logging.exception("Could not extract malware sample from ZIP file")
            return {"error": "Could not extract malware sample from ZIP file"}

    try:
        status, reason = clamav.instream(io.BytesIO(data))["stream"]
    except Exception:
        logging.exception("Could not send attribute data to ClamAV. Maybe file is too big?")
        return {"error": "Could not send attribute data to ClamAV. Maybe file is too big?"}

    if status == "ERROR":
        return {"error": "ClamAV returned error message: {}".format(reason)}
    elif status == "OK":
        return {"results": {}}
    elif status == "FOUND":
        return create_response(attribute, software_version, reason)
    else:
        return {"error": "ClamAV returned invalid status {}: {}".format(status, reason)}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
