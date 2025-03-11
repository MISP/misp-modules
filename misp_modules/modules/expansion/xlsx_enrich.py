import binascii
import io
import json

import np
import pandas

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment"], "output": ["freetext", "text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Sascha Rommelfangen",
    "description": "Module to extract freetext from a .xlsx document.",
    "module-type": ["expansion"],
    "name": "XLXS Enrich",
    "logo": "xlsx.png",
    "requirements": ["pandas: Python library to perform data analysis, time series and statistics."],
    "features": (
        "The module reads the text contained in a .xlsx document. The result is passed to the freetext import parser so"
        " IoCs can be extracted out of it."
    ),
    "references": [],
    "input": "Attachment attribute containing a .xlsx document.",
    "output": "Text and freetext parsed from the document.",
}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q["attachment"]
    try:
        xlsx_array = np.frombuffer(binascii.a2b_base64(q["data"]), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors["error"] = err
        print(err)
        return misperrors

    xls_content = ""
    xls_file = io.BytesIO(xlsx_array)
    pandas.set_option("display.max_colwidth", -1)
    try:
        xls = pandas.read_excel(xls_file)
        xls_content = xls.to_string(max_rows=None)
        print(xls_content)
        return {
            "results": [
                {
                    "types": ["freetext"],
                    "values": xls_content,
                    "comment": ".xlsx-to-text from file " + filename,
                },
                {
                    "types": ["text"],
                    "values": xls_content,
                    "comment": ".xlsx-to-text from file " + filename,
                },
            ]
        }
    except Exception as e:
        print(e)
        err = "Couldn't analyze file as .xlsx. Error was: " + str(e)
        misperrors["error"] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
