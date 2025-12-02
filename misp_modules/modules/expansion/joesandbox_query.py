# -*- coding: utf-8 -*-
import json

import jbxapi
from joe_parser import JoeParser

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}

inputSource = ["link"]

moduleinfo = {
    "version": "0.2",
    "author": "Christian Studer",
    "description": (
        "Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and"
        " converted into MISP attributes and objects."
    ),
    "module-type": ["expansion"],
    "name": "Joe Sandbox Import",
    "logo": "joesandbox.png",
    "requirements": ["jbxapi: Joe Sandbox API python3 library"],
    "features": (
        "Module using the new format of modules able to return attributes and objects.\n\nThe module returns the same"
        " results as the import module"
        " [joe_import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py)"
        " taking directly the json report as input.\n\nEven if the introspection will allow all kinds of links to call"
        " this module, obviously only the ones presenting a sample or url submission in the Joe Sandbox API will return"
        " results.\n\nTo make it work you will need to fill the 'apikey' configuration with your Joe Sandbox API key"
        " and provide a valid link as input."
    ),
    "references": ["https://www.joesecurity.org", "https://www.joesandbox.com/"],
    "input": "Link of a Joe Sandbox sample or url submission.",
    "output": "MISP attributes & objects parsed from the analysis report.",
}
moduleconfig = ["apiurl", "apikey", "import_executable", "import_mitre_attack"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    apiurl = request["config"].get("apiurl") or "https://jbxcloud.joesecurity.org/api"
    apikey = request["config"].get("apikey")
    parser_config = {
        "import_executable": request["config"].get("import_executable", "false") == "true",
        "mitre_attack": request["config"].get("import_mitre_attack", "false") == "true",
    }

    if not apikey:
        return {"error": "No API key provided"}

    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error} that is the link to the Joe Sandbox report."}
    if request["attribute"]["type"] != "link":
        return {"error": "Unsupported attribute type."}
    url = request["attribute"]["value"]
    if "/submissions/" not in url:
        return {"error": "The URL does not point to a Joe Sandbox analysis."}

    submission_id = url.split("/")[-1]  # The URL has the format https://example.net/submissions/12345
    joe = jbxapi.JoeSandbox(apiurl=apiurl, apikey=apikey, user_agent="MISP joesandbox_query")

    try:
        joe_info = joe.submission_info(submission_id)
    except jbxapi.ApiError as e:
        return {"error": str(e)}

    if joe_info["status"] != "finished":
        return {"error": "The analysis has not finished yet."}

    if joe_info["most_relevant_analysis"] is None:
        return {"error": "No analysis belongs to this submission."}

    analysis_webid = joe_info["most_relevant_analysis"]["webid"]

    joe_parser = JoeParser(parser_config)
    joe_data = json.loads(joe.analysis_download(analysis_webid, "jsonfixed")[1])
    joe_parser.parse_data(joe_data["analysis"])
    joe_parser.finalize_results()

    return {"results": joe_parser.results}


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup["input"] = inputSource
    except NameError:
        pass
    modulesetup["format"] = "misp_standard"
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
