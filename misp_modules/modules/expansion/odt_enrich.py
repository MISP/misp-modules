import binascii
import io
import json

import np
from ODTReader.odtreader import odtToText

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment"], "output": ["freetext", "text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Sascha Rommelfangen",
    "description": "Module to extract freetext from a .odt document.",
    "module-type": ["expansion"],
    "name": "ODT Enrich",
    "logo": "odt.png",
    "requirements": ["ODT reader python library."],
    "features": (
        "The module reads the text contained in a .odt document. The result is passed to the freetext import parser so"
        " IoCs can be extracted out of it."
    ),
    "references": [],
    "input": "Attachment attribute containing a .odt document.",
    "output": "Text and freetext parsed from the document.",
}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q["attachment"]
    try:
        odt_array = np.frombuffer(binascii.a2b_base64(q["data"]), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors["error"] = err
        print(err)
        return misperrors

    odt_content = ""
    odt_file = io.BytesIO(odt_array)
    try:
        odt_content = odtToText(odt_file)
        print(odt_content)
        return {
            "results": [
                {
                    "types": ["freetext"],
                    "values": odt_content,
                    "comment": ".odt-to-text from file " + filename,
                },
                {
                    "types": ["text"],
                    "values": odt_content,
                    "comment": ".odt-to-text from file " + filename,
                },
            ]
        }
    except Exception as e:
        print(e)
        err = "Couldn't analyze file as .odt. Error was: " + str(e)
        misperrors["error"] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
