#!/usr/bin/env python3
"""
Module (type "import") to import a Lastline report from an analysis link.
"""
import json

import lastline_api


misperrors = {
    "error": "Error",
}

userConfig = {
    "analysis_link": {
        "type": "String",
        "errorMessage": "Expected analysis link",
        "message": "The link to a Lastline analysis"
    },
}

inputSource = []

moduleinfo = {
    "version": "0.1",
    "author": "Stefano Ortolani",
    "description": "Import a Lastline report from an analysis link.",
    "module-type": ["import"]
}

moduleconfig = [
    "username",
    "password",
    "verify_ssl",
]


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    modulesetup["format"] = "misp_standard"
    return modulesetup


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
        analysis_link = request["config"]["analysis_link"]
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
        api_client = lastline_api.PortalClient(api_url, auth_data, verify_ssl=config.get('verify_ssl', True).lower() in ("true"))
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
            key: event_dictionary[key]
            for key in ("Attribute", "Object", "Tag")
            if (key in event and event[key])
        }
    }


if __name__ == "__main__":
    """Test importing information from a Lastline analysis link."""
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
            "config": {
                **a,
                "analysis_link": (
                    "https://user.lastline.com/portal#/analyst/task/"
                    "1fcbcb8f7fb400100772d6a7b62f501b/overview"
                )
            }
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))

    j = json.dumps(
        {
            "config": {
                **a,
                "analysis_link": (
                    "https://user.lastline.com/portal#/analyst/task/"
                    "f3c0ae115d51001017ff8da768fa6049/overview"
                )
            }
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))
