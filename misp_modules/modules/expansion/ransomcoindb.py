import json

from pymisp import MISPObject

from . import check_input_attribute, checking_error, standard_error_message
from ._ransomcoindb import ransomcoindb

copyright = """
  Copyright 2019 (C) by Aaron Kaplan <aaron@lo-res.org>, all rights reserved.
  This file is part of the ransomwarecoindDB project and licensed under the AGPL 3.0 license
"""


debug = False

misperrors = {"error": "Error"}
# mispattributes = {'input': ['sha1', 'sha256', 'md5', 'btc', 'xmr', 'dash' ], 'output': ['btc', 'sha1', 'sha256', 'md5', 'freetext']}
mispattributes = {
    "input": ["sha1", "sha256", "md5", "btc"],
    "output": ["btc", "sha1", "sha256", "md5", "freetext"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "Aaron Kaplan",
    "description": "Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)",
    "module-type": ["expansion", "hover"],
    "name": "RandomcoinDB Lookup",
    "logo": "",
    "requirements": ["A ransomcoinDB API key."],
    "features": (
        "The module takes either a hash attribute or a btc attribute as input to query the ransomcoinDB API for some"
        " additional data.\n\nIf the input is a btc address, we will get the associated hashes returned in a file MISP"
        " object. If we query ransomcoinDB with a hash, the response contains the associated btc addresses returned as"
        " single MISP btc attributes."
    ),
    "references": ["https://ransomcoindb.concinnity-risks.com"],
    "input": "A hash (md5, sha1 or sha256) or btc attribute.",
    "output": "Hashes associated to a btc address or btc addresses associated to a hash.",
    "descrption": (
        "Module to access the ransomcoinDB with a hash or btc address attribute and get the associated btc address of"
        " hashes."
    ),
}
moduleconfig = ["api-key"]


def handler(q=False):
    """the main handler function which gets a JSON dict as input and returns a results dict"""

    if q is False:
        return False

    q = json.loads(q)
    if "config" not in q or "api-key" not in q["config"]:
        return {"error": "Ransomcoindb API key is missing"}
    if not q.get("attribute") or not check_input_attribute(q["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error}."}
    if q["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    api_key = q["config"]["api-key"]
    r = {"results": []}

    """ the "q" query coming in should look something like this:
        {'config': {'api-key': '<api key here>'},
         'md5': 'md5 or sha1 or sha256 or btc',
         'module': 'ransomcoindb',
         'persistent': 1}
    """
    attribute = q["attribute"]
    answer = ransomcoindb.get_data_by("BTC", attribute["type"], attribute["value"], api_key)
    """ The results data type should be:
      r =  { 'results': [ {'types': 'md5', 'values': [ a list of all md5s or all binaries related to this btc address ]  } ] }
    """
    if attribute["type"] in ["md5", "sha1", "sha256"]:
        r["results"].append({"types": "btc", "values": [a["btc"] for a in answer]})
    elif attribute["type"] == "btc":
        # better: create a MISP object
        files = []
        for a in answer:
            obj = MISPObject("file")
            obj.add_attribute("md5", a["md5"])
            obj.add_attribute("sha1", a["sha1"])
            obj.add_attribute("sha256", a["sha256"])
            files.append(obj)
        r["results"] = {"Object": [json.loads(f.to_json()) for f in files]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
