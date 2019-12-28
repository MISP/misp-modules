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
import abc
import logging
import io
import ipaddress
import pymisp
import re
import requests
from urllib import parse


DEFAULT_LL_PORTAL_API_URL = "https://user.lastline.com/papi"

DEFAULT_LL_ANALYSIS_API_URL = "https://analysis.lastline.com"

LL_HOSTED_DOMAINS = frozenset([
    "user.lastline.com",
    "user.emea.lastline.com",
])


def purge_none(d):
    """Purge None entries from a dictionary."""
    return {k: v for k, v in d.items() if v is not None}


def get_task_link(uuid, analysis_url=None, portal_url=None):
    """
    Get the task link given the task uuid and at least one API url.

    :param str uuid: the task uuid
    :param str|None analysis_url: the URL to the analysis API endpoint
    :param str|None portal_url: the URL to the portal API endpoint
    :rtype: str
    :return: the task link
    :raises ValueError: if not enough parameters have been provided
    """
    if not analysis_url and not portal_url:
        raise ValueError("Neither analysis URL or portal URL have been specified")
    if analysis_url:
        portal_url = "{}/papi".format(analysis_url.replace("analysis.", "user."))
    portal_url_path = "../portal#/analyst/task/{}/overview".format(uuid)
    return parse.urljoin(portal_url, portal_url_path)


def get_portal_url_from_task_link(task_link):
    """
    Return the portal API url related to the provided task link.

    :param str task_link: a link
    :rtype: str
    :return: the portal API url
    """
    parsed_uri = parse.urlparse(task_link)
    return "{uri.scheme}://{uri.netloc}/papi".format(uri=parsed_uri)


def get_uuid_from_task_link(task_link):
    """
    Return the uuid from a task link.

    :param str task_link: a link
    :rtype: str
    :return: the uuid
    :raises ValueError: if the link contains not task uuid
    """
    try:
        return re.findall("[a-fA-F0-9]{32}", task_link)[0]
    except IndexError:
        raise ValueError("Link does not contain a valid task uuid")


def is_task_hosted(task_link):
    """
    Return whether the portal link is pointing to a hosted submission.

    :param str task_link: a link
    :rtype: boolean
    :return: whether the link points to a hosted analysis
    """
    for domain in LL_HOSTED_DOMAINS:
        if domain in task_link:
            return True
    return False


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


class LastlineAbstractClient(abc.ABC):
    """"A very basic HTTP client providing basic functionality."""

    __metaclass__ = abc.ABCMeta

    SUB_APIS = ('analysis', 'authentication', 'knowledgebase', 'login')
    FORMATS = ["json", "xml"]

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
                "key": api_key,
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
    def get_login_params_from_dict(cls, d):
        """
        Get the module configuration from a ConfigParser object.

        :param dict[str, str] d: the dictionary
        :rtype: dict[str, str]
        :return: the parsed configuration
        """
        api_key = d.get("key")
        api_token = d.get("api_token")
        username = d.get("username")
        password = d.get("password")
        return cls.sanitize_login_params(api_key, api_token, username, password)

    @classmethod
    def get_login_params_from_conf(cls, conf, section_name):
        """
        Get the module configuration from a ConfigParser object.

        :param ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: dict[str, str]
        :return: the parsed configuration
        """
        api_key = conf.get(section_name, "key", fallback=None)
        api_token = conf.get(section_name, "api_token", fallback=None)
        username = conf.get(section_name, "username", fallback=None)
        password = conf.get(section_name, "password", fallback=None)
        return cls.sanitize_login_params(api_key, api_token, username, password)

    @classmethod
    def load_from_conf(cls, conf, section_name):
        """
        Load client from a ConfigParser object.

        :param ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: T <- LastlineAbstractClient
        :return: the loaded client
        """
        url = conf.get(section_name, "url")
        return cls(url, cls.get_login_params_from_conf(conf, section_name))

    def __init__(self, api_url, login_params, timeout=60, verify_ssl=True):
        """
        Instantiate a Lastline mini client.

        :param str api_url: the URL of the API
        :param dict[str, str]: the login parameters
        :param int timeout: the timeout
        :param boolean verify_ssl: whether to verify the SSL certificate
        """
        self._url = api_url
        self._login_params = login_params
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._session = None
        self._logger = logging.getLogger(__name__)

    @abc.abstractmethod
    def _login(self):
        """Login using account-based or key-based methods."""

    def _is_logged_in(self):
        """Return whether we have an active session."""
        return self._session is not None

    @staticmethod
    def _parse_response(response):
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

    def _handle_response(self, response, raw=False):
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
            _, err = self._parse_response(response)
            if isinstance(err, ApiError):
                err_msg = "{}: {}".format(e, err.error_msg)
            else:
                err_msg = "{}".format(e)
            raise CommunicationError(err_msg)

        # Otherwise return the data (either parsed or not) but reraise if we have an API error
        if raw:
            return response.content
        data, err = self._parse_response(response)
        if err:
            raise err
        return data

    def _build_url(self, sub_api, parts, requested_format="json"):
        if sub_api not in self.SUB_APIS:
            raise InvalidArgument(sub_api)
        if requested_format not in self.FORMATS:
            raise InvalidArgument(requested_format)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts) + ".%s"
        params = [self._url, sub_api] + parts + [requested_format]
        return pattern % tuple(params)

    def post(self, module, function, params=None, data=None, files=None, fmt="json"):
        if isinstance(function, list):
            functions = function
        else:
            functions = [function] if function else []
        url = self._build_url(module, functions, requested_format=fmt)
        return self.do_request(
            url=url,
            method="POST",
            params=params,
            data=data,
            files=files,
            fmt=fmt,
        )

    def get(self, module, function, params=None, fmt="json"):
        if isinstance(function, list):
            functions = function
        else:
            functions = [function] if function else []
        url = self._build_url(module, functions, requested_format=fmt)
        return self.do_request(
            url=url,
            method="GET",
            params=params,
            fmt=fmt,
        )

    def do_request(
        self,
        method,
        url,
        params=None,
        data=None,
        files=None,
        fmt="json",
        raw=False,
        raw_response=False,
        headers=None,
        stream_response=False
    ):
        if raw_response:
            raw = True

        if fmt:
            fmt = fmt.lower().strip()
            if fmt not in self.FORMATS:
                raise InvalidArgument("Only json, xml, html and pdf supported")
        elif not raw:
            raise InvalidArgument("Unformatted response requires raw=True")

        if fmt != "json" and not raw:
            raise InvalidArgument("Non-json format requires raw=True")

        if method not in ["POST", "GET"]:
            raise InvalidArgument("Only POST and GET supported")

        if not self._is_logged_in():
            self._login()

        try:
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    data=data,
                    params=params,
                    files=files,
                    verify=self._verify_ssl,
                    timeout=self._timeout,
                    stream=stream_response,
                    headers=headers,
                )
            except requests.RequestException as e:
                raise CommunicationError(e)

            if raw_response:
                return response
            return self._handle_response(response, raw)

        except Error as e:
            raise e

        except CommunicationError as e:
            raise e


class AnalysisClient(LastlineAbstractClient):

    def _login(self):
        """
        Creates auth session for malscape-service.

        Credentials are 'key' and 'api_token'.
        """
        if self._session is None:
            self._session = requests.session()
        url = self._build_url("authentication", ["login"])
        self.do_request("POST", url, params=purge_none(self._login_params))

    def get_progress(self, uuid):
        """
        Get the completion progress of a given task.
        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, int]
        :return: a dictionary like the the following:
            {
                "completed": 1,
                "progress": 100
            }
        """
        url = self._build_url('analysis', ['get_progress'])
        params = {'uuid': uuid}
        return self.do_request("POST", url, params=params)

    def get_result(self, uuid):
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, any]
        :return: a dictionary like the the following:
            {
                "completed": 1,
                "progress": 100
            }
        """
        # better: use 'get_results()' but that would break
        # backwards-compatibility
        url = self._build_url('analysis', ['get'])
        params = {'uuid': uuid}
        return self.do_request("GET", url, params=params)

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
        file_stream = io.BytesIO(file_data)
        api_url = self._build_url("analysis", ["submit", "file"])
        params = purge_none({
            "bypass_cache": bypass_cache and 1 or None,
            "analysis_timeout": analysis_timeout,
            "analysis_env": analysis_env,
            "allow_network_traffic": allow_network_traffic and 1 or None,
            "filename": file_name,
            "password": password,
            "full_report_score": -1,
        })

        files = purge_none({
            # If an explicit filename was provided, we can pass it down to
            # python-requests to use it in the multipart/form-data. This avoids
            # having python-requests trying to guess the filename based on stream
            # attributes.
            #
            # The problem with this is that, if the filename is not ASCII, then
            # this triggers a bug in flask/werkzeug which means the file is
            # thrown away. Thus, we just force an ASCII name
            "file": ('dummy-ascii-name-for-file-param', file_stream),
        })

        return self.do_request("POST", api_url, params=params, files=files)

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
        api_url = self._build_url("analysis", ["submit", "url"])
        params = purge_none({
            "url": url,
            "referer": referer,
            "bypass_cache": bypass_cache and 1 or None,
            "user_agent": user_agent or None,
        })
        return self.do_request("POST", api_url, params=params)


class PortalClient(LastlineAbstractClient):

    def _login(self):
        """
        Login using account-based or key-based methods.

        Credentials are 'username' and 'password'
        """
        if self._session is None:
            self._session = requests.session()
        self.post("login", function=None, data=self._login_params)

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
        return self.get("analysis", "get_progress", params=params)

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
        return self.get("analysis", "get_result", params=params)

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
        return self.post("analysis", "submit_url", params=params)

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
        return self.post("analysis", "submit_file", params=params, files=files)


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
        sandbox_type = "saas" if is_task_hosted(analysis_link) else "on-premise"
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
