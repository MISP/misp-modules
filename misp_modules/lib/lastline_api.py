"""
Lastline Community API Client and Utilities.

:Copyright:
    Copyright 2019 Lastline, Inc.  All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Copyright (c) 2010-2012 by Internet Systems Consortium, Inc. ("ISC")

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""
import ipaddress
import logging
import re
import requests
import pymisp

from urllib import parse


DEFAULT_LASTLINE_API = "https://user.lastline.com/papi"


HOSTED_LASTLINE_DOMAINS = frozenset([
    "user.lastline.com",
    "user.emea.lastline.com",
])


def purge_none(d):
    """Purge None entries from a dictionary."""
    return {k: v for k, v in d.items() if v is not None}


def get_analysis_link(api_url, uuid):
    """
    Get the analysis link of a task given the task uuid.

    :param str api_url: the URL
    :param str uuid: the task uuid
    :rtype: str
    :return: the analysis link
    """
    portal_url_path = "../portal#/analyst/task/{}/overview".format(uuid)
    analysis_link = parse.urljoin(api_url, portal_url_path)
    return analysis_link


def get_uuid_from_link(analysis_link):
    """
    Return task uuid from link or raise ValueError exception.

    :param str analysis_link: a link
    :rtype: str
    :return: the uuid
    :raises ValueError: if the link contains not task uuid
    """
    try:
        return re.findall("[a-fA-F0-9]{32}", analysis_link)[0]
    except IndexError:
        raise ValueError("Link does not contain a valid task uuid")


def is_analysis_hosted(analysis_link):
    """
    Return whether the analysis link is pointing to a hosted submission.

    :param str analysis_link: a link
    :rtype: boolean
    :return: whether the link is hosted
    """
    for domain in HOSTED_LASTLINE_DOMAINS:
        if domain in analysis_link:
            return True
    return False


def get_api_url_from_link(analysis_link):
    """
    Return the API url related to the provided analysis link.

    :param str analysis_link: a link
    :rtype: str
    :return: the API url
    """
    parsed_uri = parse.urlparse(analysis_link)
    return "{uri.scheme}://{uri.netloc}/papi".format(uri=parsed_uri)


class InvalidArgument(Exception):
    """Error raised invalid."""


class CommunicationError(Exception):
    """Exception raised in case of timeouts or other network problem."""


class Error(Exception):
    """Generic server error."""


class ApiError(Error):
    """Server error with a message and an error code."""
    def __init__(self, error_msg, error_code=None):
        super(ApiError, self).__init__(error_msg, error_code)
        self.error_msg = error_msg
        self.error_code = error_code

    def __str__(self):
        if self.error_code is None:
            error_code = ""
        else:
            error_code = " ({})".format(self.error_code)
        return "{}{}".format(self.error_msg, error_code)


class LastlineResultBaseParser(object):
    """
    This is a parser to extract *basic* information from a Lastline result dictionary.

    Note: this is a *version 0*: the information we extract is merely related to the behaviors and
        the HTTP connections. Further iterations will include host activity such as files, mutexes,
        registry keys, strings, etc.
    """

    def __init__(self):
        """Constructor."""
        self.misp_event = None

    @staticmethod
    def _get_mitre_techniques(result):
        return [
            "misp-galaxy:mitre-attack-pattern=\"{} - {}\"".format(w[0], w[1])
            for w in sorted(set([
                (y["id"], y["name"])
                for x in result.get("malicious_activity", [])
                for y in result.get("activity_to_mitre_techniques", {}).get(x, [])
            ]))
        ]

    def parse(self, analysis_link, result):
        """
        Parse the analysis result into a MISP event.

        :param str analysis_link: the analysis link
        :param dict[str, any] result: the JSON returned by the analysis client.
        :rtype: MISPEvent
        :return: some results that can be consumed by MIPS.
        """
        self.misp_event = pymisp.MISPEvent()

        # Add analysis subject info
        if "url" in result["analysis_subject"]:
            o = pymisp.MISPObject("url")
            o.add_attribute("url", result["analysis_subject"]["url"])
        else:
            o = pymisp.MISPObject("file")
            o.add_attribute("md5", type="md5", value=result["analysis_subject"]["md5"])
            o.add_attribute("sha1", type="sha1", value=result["analysis_subject"]["sha1"])
            o.add_attribute("sha256", type="sha256", value=result["analysis_subject"]["sha256"])
            o.add_attribute(
                "mimetype",
                type="mime-type",
                value=result["analysis_subject"]["mime_type"]
            )
        self.misp_event.add_object(o)

        # Add HTTP requests from url analyses
        network_dict = result.get("report", {}).get("analysis", {}).get("network", {})
        for request in network_dict.get("requests", []):
            parsed_uri = parse.urlparse(request["url"])
            o = pymisp.MISPObject(name='http-request')
            o.add_attribute('host', parsed_uri.netloc)
            o.add_attribute('method', "GET")
            o.add_attribute('uri', request["url"])
            o.add_attribute("ip", request["ip"])
            self.misp_event.add_object(o)

        # Add network behaviors from files
        for subject in result.get("report", {}).get("analysis_subjects", []):

            # Add DNS requests
            for dns_query in subject.get("dns_queries", []):
                hostname = dns_query.get("hostname")
                # Skip if it is an IP address
                try:
                    if hostname == "wpad":
                        continue
                    _ = ipaddress.ip_address(hostname)
                    continue
                except ValueError:
                    pass

                o = pymisp.MISPObject(name='dns-record')
                o.add_attribute('queried-domain', hostname)
                self.misp_event.add_object(o)

            # Add HTTP conversations (as network connection and as http request)
            for http_conversation in subject.get("http_conversations", []):
                o = pymisp.MISPObject(name="network-connection")
                o.add_attribute("ip-src", http_conversation["src_ip"])
                o.add_attribute("ip-dst", http_conversation["dst_ip"])
                o.add_attribute("src-port", http_conversation["src_port"])
                o.add_attribute("dst-port", http_conversation["dst_port"])
                o.add_attribute("hostname-dst", http_conversation["dst_host"])
                o.add_attribute("layer3-protocol", "IP")
                o.add_attribute("layer4-protocol", "TCP")
                o.add_attribute("layer7-protocol", "HTTP")
                self.misp_event.add_object(o)

                method, path, http_version = http_conversation["url"].split(" ")
                if http_conversation["dst_port"] == 80:
                    uri = "http://{}{}".format(http_conversation["dst_host"], path)
                else:
                    uri = "http://{}:{}{}".format(
                        http_conversation["dst_host"],
                        http_conversation["dst_port"],
                        path
                    )
                o = pymisp.MISPObject(name='http-request')
                o.add_attribute('host', http_conversation["dst_host"])
                o.add_attribute('method', method)
                o.add_attribute('uri', uri)
                o.add_attribute('ip', http_conversation["dst_ip"])
                self.misp_event.add_object(o)

        # Add sandbox info like score and sandbox type
        o = pymisp.MISPObject(name="sandbox-report")
        sandbox_type = "saas" if is_analysis_hosted(analysis_link) else "on-premise"
        o.add_attribute("score", result["score"])
        o.add_attribute("sandbox-type", sandbox_type)
        o.add_attribute("{}-sandbox".format(sandbox_type), "lastline")
        o.add_attribute("permalink", analysis_link)
        self.misp_event.add_object(o)

        # Add behaviors
        o = pymisp.MISPObject(name="sb-signature")
        o.add_attribute("software", "Lastline")
        for activity in result.get("malicious_activity", []):
            a = pymisp.MISPAttribute()
            a.from_dict(type="text", value=activity)
            o.add_attribute("signature", **a)
        self.misp_event.add_object(o)

        # Add mitre techniques
        for technique in self._get_mitre_techniques(result):
            self.misp_event.add_tag(technique)


class LastlineCommunityHTTPClient(object):
    """"A very basic HTTP client providing basic functionality."""

    @classmethod
    def sanitize_login_params(cls, api_key, api_token, username, password):
        """
        Return a dictionary with either API or USER credentials.

        :param str|None api_key: the API key
        :param str|None api_token: the API token
        :param str|None username: the username
        :param str|None password: the password
        :rtype: dict[str, str]
        :return: the dictionary
        :raises InvalidArgument: if too many values are invalid
        """
        if api_key and api_token:
            return {
                "api_key": api_key,
                "api_token": api_token,
            }
        elif username and password:
            return {
                "username": username,
                "password": password,
            }
        else:
            raise InvalidArgument("Arguments provided do not contain valid data")

    @classmethod
    def get_login_params_from_conf(cls, conf, section_name):
        """
        Get the module configuration from a ConfigParser object.

        :param ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: dict[str, str]
        :return: the parsed configuration
        """
        api_key = conf.get(section_name, "api_key", fallback=None)
        api_token = conf.get(section_name, "api_token", fallback=None)
        username = conf.get(section_name, "username", fallback=None)
        password = conf.get(section_name, "password", fallback=None)
        return cls.sanitize_login_params(api_key, api_token, username, password)

    @classmethod
    def get_login_params_from_request(cls, request):
        """
        Get the module configuration from a ConfigParser object.

        :param dict[str, any] request: the request object
        :rtype: dict[str, str]
        :return: the parsed configuration
        """
        api_key = request.get("config", {}).get("api_key")
        api_token = request.get("config", {}).get("api_token")
        username = request.get("config", {}).get("username")
        password = request.get("config", {}).get("password")
        return cls.sanitize_login_params(api_key, api_token, username, password)

    def __init__(self, api_url, login_params, timeout=60, verify_ssl=True):
        """
        Instantiate a Lastline mini client.

        :param str api_url: the URL of the API
        :param dict[str, str]: the login parameters
        :param int timeout: the timeout
        :param boolean verify_ssl: whether to verify the SSL certificate
        """
        self.__url = api_url
        self.__login_params = login_params
        self.__timeout = timeout
        self.__verify_ssl = verify_ssl
        self.__session = None
        self.__logger = logging.getLogger(__name__)

    def __login(self):
        """Login using account-based or key-based methods."""
        if self.__session is None:
            self.__session = requests.session()

        login_url = "/".join([self.__url, "login"])
        try:
            response = self.__session.request(
                method="POST",
                url=login_url,
                data=self.__login_params,
                verify=self.__verify_ssl,
                timeout=self.__timeout,
                proxies=None,
            )
        except requests.RequestException as e:
            raise CommunicationError(e)

        self.__handle_response(response)

    def __is_logged_in(self):
        """Return whether we have an active session."""
        return self.__session is not None

    @staticmethod
    def __parse_response(response):
        """
        Parse the response.

        :param requests.Response response: the response
        :rtype: tuple(str|None, Error|ApiError)
        :return: a tuple with mutually exclusive fields (either the response or the error)
        """
        try:
            ret = response.json()
            if "success" not in ret:
                return None, Error("no success field in response")

            if not ret["success"]:
                error_msg = ret.get("error", "")
                error_code = ret.get("error_code", None)
                return None, ApiError(error_msg, error_code)

            if "data" not in ret:
                return None, Error("no data field in response")

            return ret["data"], None
        except ValueError as e:
            return None, Error("Response not json {}".format(e))

    def __handle_response(self, response, raw=False):
        """
        Check a response for issues and parse the return.

        :param requests.Response response: the response
        :param boolean raw: whether the raw body should be returned
        :rtype: str
        :return: if raw, return the response content; if not raw, the data field
        :raises: CommunicationError, ApiError, Error
        """
        # Check for HTTP errors, and re-raise in case
        try:
            response.raise_for_status()
        except requests.RequestException as e:
            _, err = self.__parse_response(response)
            if isinstance(err, ApiError):
                err_msg = "{}: {}".format(e, err.error_msg)
            else:
                err_msg = "{}".format(e)
            raise CommunicationError(err_msg)

        # Otherwise return the data (either parsed or not) but reraise if we have an API error
        if raw:
            return response.content
        data, err = self.__parse_response(response)
        if err:
            raise err
        return data

    def do_request(
        self,
        method,
        module,
        function,
        params=None,
        data=None,
        files=None,
        url=None,
        fmt="JSON",
        raw=False,
        raw_response=False,
        headers=None,
        stream_response=False
    ):
        if raw_response:
            raw = True

        if fmt:
            fmt = fmt.lower().strip()
            if fmt not in ["json", "xml", "html", "pdf"]:
                raise InvalidArgument("Only json, xml, html and pdf supported")
        elif not raw:
            raise InvalidArgument("Unformatted response requires raw=True")

        if fmt != "json" and not raw:
            raise InvalidArgument("Non-json format requires raw=True")

        if method not in ["POST", "GET"]:
            raise InvalidArgument("Only POST and GET supported")

        function = function.strip(" /")
        if not function:
            raise InvalidArgument("No function provided")

        # Login after we verified that all arguments are fine
        if not self.__is_logged_in():
            self.__login()

        url_parts = [url or self.__url]
        module = module.strip(" /")
        if module:
            url_parts.append(module)
        if fmt:
            function_part = "%s.%s" % (function, fmt)
        else:
            function_part = function
        url_parts.append(function_part)
        url = "/".join(url_parts)

        try:
            try:
                response = self.__session.request(
                    method=method,
                    url=url,
                    data=data,
                    params=params,
                    files=files,
                    verify=self.__verify_ssl,
                    timeout=self.__timeout,
                    stream=stream_response,
                    headers=headers,
                )
            except requests.RequestException as e:
                raise CommunicationError(e)

            if raw_response:
                return response
            return self.__handle_response(response, raw)

        except Error as e:
            raise e

        except CommunicationError as e:
            raise e


class LastlineCommunityAPIClient(object):
    """"A very basic API client providing basic functionality."""

    def __init__(self, api_url, login_params):
        """
        Instantiate the API client.

        :param str api_url: the URL to the API server
        :param dict[str, str] login_params: the login parameters
        """
        self._client = LastlineCommunityHTTPClient(api_url, login_params)
        self._logger = logging.getLogger(__name__)

    def _post(self, module, function, params=None, data=None, files=None, fmt="JSON"):
        return self._client.do_request(
            method="POST",
            module=module,
            function=function,
            params=params,
            data=data,
            files=files,
            fmt=fmt,
        )

    def _get(self, module, function, params=None, fmt="JSON"):
        return self._client.do_request(
            method="GET",
            module=module,
            function=function,
            params=params,
            fmt=fmt,
        )

    def get_progress(self, uuid, analysis_instance=None):
        """
        Get the completion progress of a given task.

        :param str uuid: the unique identifier of the submitted task
        :param str analysis_instance: if set, defines the analysis instance to query
        :rtype: dict[str, int]
        :return: a dictionary like the the following:
            {
                "completed": 1,
                "progress": 100
            }
        """
        params = purge_none({"uuid": uuid, "analysis_instance": analysis_instance})
        return self._get("analysis", "get_progress", params=params)

    def get_result(self, uuid, analysis_instance=None):
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :param str analysis_instance: if set, defines the analysis instance to query
        :rtype: dict[str, any]
        :return: a dictionary like the the following:
            {
                "completed": 1,
                "progress": 100
            }
        """
        params = purge_none(
            {
                "uuid": uuid,
                "analysis_instance": analysis_instance,
                "report_format": "json",
            }
        )
        return self._get("analysis", "get_result", params=params)

    def submit_url(
        self,
        url,
        referer=None,
        user_agent=None,
        bypass_cache=False,
    ):
        """
        Upload an URL to be analyzed.

        :param str url: the url to analyze
        :param str|None referer: the referer
        :param str|None user_agent: the user agent
        :param boolean bypass_cache: bypass_cache
        :rtype: dict[str, any]
        :return: a dictionary like the following if the analysis is already available:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        params = purge_none(
            {
                "url": url,
                "bypass_cache": bypass_cache,
                "referer": referer,
                "user_agent": user_agent
            }
        )
        return self._post(module="analysis", function="submit_url", params=params)

    def submit_file(
        self,
        file_data,
        file_name=None,
        password=None,
        analysis_env=None,
        allow_network_traffic=True,
        analysis_timeout=None,
        bypass_cache=False,
    ):
        """
        Upload a file to be analyzed.

        :param bytes file_data: the data as a byte sequence
        :param str|None file_name: if set, represents the name of the file to submit
        :param str|None password: if set, use it to extract the sample
        :param str|None analysis_env: if set, e.g windowsxp
        :param boolean allow_network_traffic: if set to False, deny network connections
        :param int|None analysis_timeout: if set limit the duration of the analysis
        :param boolean bypass_cache: whether to re-process a file (requires special permissions)
        :rtype: dict[str, any]
        :return: a dictionary in the following form if the analysis is already available:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        params = purge_none(
            {
                "filename": file_name,
                "password": password,
                "analysis_env": analysis_env,
                "allow_network_traffic": allow_network_traffic,
                "analysis_timeout": analysis_timeout,
                "bypass_cache": bypass_cache,
            }
        )
        files = {"file": (file_name, file_data, "application/octet-stream")}
        return self._post(module="analysis", function="submit_file", params=params, files=files)
