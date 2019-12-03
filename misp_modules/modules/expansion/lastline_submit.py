#!/usr/bin/env python3
"""
Module (type "expansion") to submit files and URLs to Lastline for analysis.
"""
import base64
import io
import json
import zipfile

import lastline_api


misperrors = {
    "error": "Error",
}

mispattributes = {
    "input": [
        "attachment",
        "malware-sample",
        "url",
    ],
    "output": [
        "link",
    ],
}

moduleinfo = {
    "version": "0.1",
    "author": "Stefano Ortolani",
    "description": "Submit files and URLs to Lastline analyst",
    "module-type": ["expansion", "hover"],
}

moduleconfig = [
    "api_url",
    "api_key",
    "api_token",
    "username",
    "password",
    # Module options
    "bypass_cache",
]


DEFAULT_ZIP_PASSWORD = b"infected"


def __unzip(zipped_data, password=None):
    data_file_object = io.BytesIO(zipped_data)
    with zipfile.ZipFile(data_file_object) as zip_file:
        sample_hashname = zip_file.namelist()[0]
        data_zipped = zip_file.read(sample_hashname, password)
    return data_zipped


def __str_to_bool(x):
    return x in ("True", "true", True)


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
        auth_data = lastline_api.LastlineCommunityHTTPClient.get_login_params_from_request(request)
        api_url = request.get("config", {}).get("api_url", lastline_api.DEFAULT_LASTLINE_API)
    except Exception as e:
        misperrors["error"] = "Error parsing configuration: {}".format(e)
        return misperrors

    # Parse the call parameters
    try:
        bypass_cache = request.get("config", {}).get("bypass_cache", False)
        call_args = {"bypass_cache": __str_to_bool(bypass_cache)}
        if "url" in request:
            # URLs are text strings
            api_method = lastline_api.LastlineCommunityAPIClient.submit_url
            call_args["url"] = request.get("url")
        else:
            data = request.get("data")
            # Malware samples are zip-encrypted and then base64 encoded
            if "malware-sample" in request:
                api_method = lastline_api.LastlineCommunityAPIClient.submit_file
                call_args["file_data"] = __unzip(base64.b64decode(data), DEFAULT_ZIP_PASSWORD)
                call_args["file_name"] = request.get("malware-sample").split("|", 1)[0]
                call_args["password"] = DEFAULT_ZIP_PASSWORD
            # Attachments are just base64 encoded
            elif "attachment" in request:
                api_method = lastline_api.LastlineCommunityAPIClient.submit_file
                call_args["file_data"] = base64.b64decode(data)
                call_args["file_name"] = request.get("attachment")

            else:
                raise ValueError("Input parameters do not specify either an URL or a file")

    except Exception as e:
        misperrors["error"] = "Error processing input parameters: {}".format(e)
        return misperrors

    # Make the API call
    try:
        api_client = lastline_api.LastlineCommunityAPIClient(api_url, auth_data)
        response = api_method(api_client, **call_args)
        task_uuid = response.get("task_uuid")
        if not task_uuid:
            raise ValueError("Unable to process returned data")
        if response.get("score") is not None:
            tags = ["workflow:state='complete'"]
        else:
            tags = ["workflow:state='incomplete'"]

    except Exception as e:
        misperrors["error"] = "Error issuing the API call: {}".format(e)
        return misperrors

    # Assemble and return
    analysis_link = lastline_api.get_analysis_link(api_url, task_uuid)

    return {
        "results": [
            {
                "types": "link",
                "categories": ["External analysis"],
                "values": analysis_link,
                "tags": tags,
            },
        ]
    }


if __name__ == "__main__":
    """Test submitting a test subject to the Lastline backend."""
    import argparse
    import configparser

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config-file", dest="config_file")
    parser.add_argument("-s", "--section-name", dest="section_name")
    args = parser.parse_args()
    c = configparser.ConfigParser()
    c.read(args.config_file)
    a = lastline_api.LastlineCommunityHTTPClient.get_login_params_from_conf(c, args.section_name)

    j = json.dumps(
        {
            "config": a,
            "url": "https://www.google.com",
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))

    with open("./tests/test_files/test.docx", "rb") as f:
        data = f.read()

    j = json.dumps(
        {
            "config": a,
            "data": base64.b64encode(data).decode("utf-8"),
            "attachment": "test.docx",
        }
    )
    print(json.dumps(handler(j), indent=4, sort_keys=True))
