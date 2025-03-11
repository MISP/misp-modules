#!/usr/bin/env python3
"""
Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Module (type "expansion") to query a Lastline report from an analysis link.
"""
import json

import lastline_api

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {
    "error": "Error",
}

mispattributes = {
    "input": [
        "link",
    ],
    "output": ["text"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.1",
    "author": "Stefano Ortolani",
    "description": (
        "Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.\n\nQuery"
        " Lastline with an analysis link and parse the report into MISP attributes and objects."
    ),
    "module-type": ["expansion"],
    "name": "Lastline Lookup",
    "logo": "lastline.png",
    "requirements": [],
    "features": (
        "The module requires a Lastline Portal `username` and `password`.\nThe module uses the new format and it is"
        " able to return MISP attributes and objects.\nThe module returns the same results as the"
        " [lastline_import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py)"
        " import module."
    ),
    "references": ["https://www.lastline.com"],
    "input": "Link to a Lastline analysis.",
    "output": "MISP attributes and objects parsed from the analysis report.",
}

moduleconfig = [
    "username",
    "password",
    "verify_ssl",
]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    # Parse the init parameters
    try:
        config = request["config"]
        auth_data = lastline_api.LastlineAbstractClient.get_login_params_from_dict(config)
        if not request.get("attribute") or not check_input_attribute(
            request["attribute"], requirements=("type", "value")
        ):
            return {"error": f"{standard_error_message}, {checking_error} that is the link to a Lastline analysis."}
        analysis_link = request["attribute"]["value"]
        # The API url changes based on the analysis link host name
        api_url = lastline_api.get_portal_url_from_task_link(analysis_link)
    except Exception as e:
        misperrors["error"] = "Error parsing configuration: {}".format(e)
        return misperrors

    # Parse the call parameters
    try:
        task_uuid = lastline_api.get_uuid_from_task_link(analysis_link)
    except (KeyError, ValueError) as e:
        misperrors["error"] = "Error processing input parameters: {}".format(e)
        return misperrors

    # Make the API calls
    try:
        api_client = lastline_api.PortalClient(
            api_url,
            auth_data,
            verify_ssl=config.get("verify_ssl", True).lower() in ("true"),
        )
        response = api_client.get_progress(task_uuid)
        if response.get("completed") != 1:
            raise ValueError("Analysis is not finished yet.")

        response = api_client.get_result(task_uuid)
        if not response:
            raise ValueError("Analysis report is empty.")

    except Exception as e:
        misperrors["error"] = "Error issuing the API call: {}".format(e)
        return misperrors

    # Parse and return
    result_parser = lastline_api.LastlineResultBaseParser()
    result_parser.parse(analysis_link, response)

    event = result_parser.misp_event
    event_dictionary = json.loads(event.to_json())

    return {
        "results": {
            key: event_dictionary[key] for key in ("Attribute", "Object", "Tag") if (key in event and event[key])
        }
    }


if __name__ == "__main__":
    """Test querying information from a Lastline analysis link."""
    import argparse
    import configparser

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config-file", dest="config_file")
    parser.add_argument("-s", "--section-name", dest="section_name")
    args = parser.parse_args()
    c = configparser.ConfigParser()
    c.read(args.config_file)
    a = lastline_api.LastlineAbstractClient.get_login_params_from_conf(c, args.section_name)

    j = json.dumps(
        {
            "config": a,
            "attribute": {
                "value": "https://user.lastline.com/portal#/analyst/task/1fcbcb8f7fb400100772d6a7b62f501b/overview"
            },
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))

    j = json.dumps(
        {
            "config": a,
            "attribute": {
                "value": "https://user.lastline.com/portal#/analyst/task/f3c0ae115d51001017ff8da768fa6049/overview"
            },
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))
