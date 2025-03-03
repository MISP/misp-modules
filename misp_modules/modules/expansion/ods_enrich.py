import binascii
import io
import json
import logging

import ezodf
import np
import pandas_ods_reader

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment"], "output": ["freetext", "text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Sascha Rommelfangen",
    "description": "Module to extract freetext from a .ods document.",
    "module-type": ["expansion"],
    "name": "ODS Enrich",
    "logo": "ods.png",
    "requirements": [
        "ezodf: Python package to create/manipulate OpenDocumentFormat files.",
        "pandas_ods_reader: Python library to read in ODS files.",
    ],
    "features": (
        "The module reads the text contained in a .ods document. The result is passed to the freetext import parser so"
        " IoCs can be extracted out of it."
    ),
    "references": [],
    "input": "Attachment attribute containing a .ods document.",
    "output": "Text and freetext parsed from the document.",
}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q["attachment"]
    try:
        ods_array = np.frombuffer(binascii.a2b_base64(q["data"]), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors["error"] = err
        print(err)
        return misperrors

    ods_content = ""
    ods_file = io.BytesIO(ods_array)
    doc = ezodf.opendoc(ods_file)
    num_sheets = len(doc.sheets)
    try:
        for i in range(0, num_sheets):
            rows = pandas_ods_reader.parsers.ods.get_rows(doc, i)
            try:
                ods = pandas_ods_reader.algo.parse_data(
                    pandas_ods_reader.parsers.ods,
                    rows,
                    headers=False,
                    columns=[],
                    skiprows=0,
                )
                ods = pandas_ods_reader.utils.sanitize_df(ods)
            except TypeError:
                ods = pandas_ods_reader.algo.read_data(pandas_ods_reader.parsers.ods, ods_file, i, headers=False)
            ods_content = ods_content + "\n" + ods.to_string(max_rows=None)
        return {
            "results": [
                {
                    "types": ["freetext"],
                    "values": ods_content,
                    "comment": ".ods-to-text from file " + filename,
                },
                {
                    "types": ["text"],
                    "values": ods_content,
                    "comment": ".ods-to-text from file " + filename,
                },
            ]
        }
    except Exception as e:
        logging.exception(e)
        err = "Couldn't analyze file as .ods. Error was: " + str(e)
        misperrors["error"] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
