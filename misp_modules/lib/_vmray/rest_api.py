#!/usr/bin/python3
"""Python client library for VMRay REST API"""

import base64
import datetime
import os.path
import urllib.parse

import requests


class VMRayRESTAPIError(Exception):
    """Exception class that is used when API returns an error"""

    def __init__(self, *args, **kwargs):
        self.status_code = kwargs.pop("status_code", None)
        Exception.__init__(self, *args, **kwargs)


def handle_rest_api_result(result):
    """Handle result of API request (check for errors)"""

    if (result.status_code < 200) or (result.status_code > 299):
        try:
            json_result = result.json()
        except ValueError:
            raise VMRayRESTAPIError(
                "API returned error %u: %s" % (result.status_code, result.text),
                status_code=result.status_code,
            )

        raise VMRayRESTAPIError(
            json_result.get("error_msg", "Unknown error"),
            status_code=result.status_code,
        )


class VMRayRESTAPI(object):
    """VMRay REST API class"""

    def __init__(self, server, api_key, verify_cert=True):
        # split server URL into components
        url_desc = urllib.parse.urlsplit(server)

        # assume HTTPS if no scheme is specified
        if url_desc.scheme == "":
            server = "https://" + server

        # save variables
        self.server = server
        self.api_key = api_key
        self.verify_cert = verify_cert

    def call(self, http_method, api_path, params=None, raw_data=False):
        """Call VMRay REST API"""

        # get function of requests package
        requests_func = getattr(requests, http_method.lower())

        # parse parameters
        req_params = {}
        file_params = {}

        if params is not None:
            for key, value in params.items():
                if isinstance(value, (datetime.date, datetime.datetime, float, int)):
                    req_params[key] = str(value)
                elif isinstance(value, str):
                    req_params[key] = str(value)
                elif isinstance(value, dict):
                    filename = value["filename"]
                    sample = value["data"]
                    file_params[key] = (filename, sample, "application/octet-stream")
                elif hasattr(value, "read"):
                    filename = os.path.split(value.name)[1]
                    # For the following block refer to DEV-1820
                    try:
                        filename.decode("ASCII")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        b64_key = key + "name_b64enc"
                        byte_value = filename.encode("utf-8")
                        b64_value = base64.b64encode(byte_value)

                        filename = "@param=%s" % b64_key
                        req_params[b64_key] = b64_value
                    file_params[key] = (filename, value, "application/octet-stream")
                else:
                    raise VMRayRESTAPIError('Parameter "%s" has unknown type "%s"' % (key, type(value)))

        # construct request
        if file_params:
            files = file_params
        else:
            files = None

        # we need to adjust some stuff for POST requests
        if http_method.lower() == "post":
            req_data = req_params
            req_params = None
        else:
            req_data = None

        # do request
        result = requests_func(
            self.server + api_path,
            data=req_data,
            params=req_params,
            headers={"Authorization": "api_key " + self.api_key},
            files=files,
            verify=self.verify_cert,
            stream=raw_data,
        )
        handle_rest_api_result(result)

        if raw_data:
            return result.raw

        # parse result
        try:
            json_result = result.json()
        except ValueError:
            raise ValueError("API returned invalid JSON: %s" % (result.text))

        # if there are no cached elements then return the data
        if "continuation_id" not in json_result:
            return json_result.get("data", None)

        data = json_result["data"]

        # get cached results
        while "continuation_id" in json_result:
            # send request to server
            result = requests.get(
                "%s/rest/continuation/%u" % (self.server, json_result["continuation_id"]),
                headers={"Authorization": "api_key " + self.api_key},
                verify=self.verify_cert,
            )
            handle_rest_api_result(result)

            # parse result
            try:
                json_result = result.json()
            except ValueError:
                raise ValueError("API returned invalid JSON: %s" % (result.text))

            data.extend(json_result["data"])

        return data
