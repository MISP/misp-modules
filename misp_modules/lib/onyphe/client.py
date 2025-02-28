import json
import logging
import os
from urllib.parse import urljoin

from onyphe.exception import APIError, ParamError

"""
onyphe.client
~~~~~~~~~~~~~

This module implements the Onyphe API.

:copyright: (c) 2017- by Sebastien Larinier
"""
import requests
from requests.utils import quote


class Onyphe:
    """Wrapper around the Onyphe REST

    :param key: The Onyphe API key that can be obtained from your account page (https://www.onyphe.io)
    :type key: str
    """

    def __init__(self, api_key, version="v2"):
        self.api_key = api_key
        self.base_url = "https://www.onyphe.io/api/"
        self.version = version
        self._session = requests

        self.methods = {
            "get": self._session.get,
            "post": self._session.post,
        }

    def _choose_url(self, uri):
        self.url = urljoin(self.base_url, uri)

    def _request(self, method, payload, json_data, files):

        data = None
        session = self.methods[method]
        try:
            if json_data:
                response = session(self.url, params=payload, data=json.dumps(json_data))
            elif files:
                payload["Content-Type"] = "application/json"
                response = session(self.url, params=payload, data=files)
            else:
                response = self.methods[method](self.url, params=payload)
        except:
            raise APIError("Unable to connect to Onyphe")

        if response.status_code == requests.codes.NOT_FOUND:

            raise APIError("Page Not found %s" % self.url)
        elif response.status_code == requests.codes.FORBIDDEN:
            raise APIError("Access Forbidden")
        elif response.status_code == requests.codes.too_many_requests:
            raise APIError("Too Many Requests")
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()["text"]
            except Exception as e:
                error = "Unknown error"

            raise APIError(error)
        try:
            data = response.json()
            return data

        except:
            return response

    def _prepare_request(self, uri, **kwargs):
        params = {"apikey": self.api_key}

        json_data = None

        files = None

        if "page" in kwargs:
            params["page"] = kwargs["page"]

        if "json_data" in kwargs:
            json_data = kwargs["json_data"]
        if "files" in kwargs:
            files = kwargs["files"]

        method = kwargs["method"]

        self._choose_url(uri)

        data = self._request(method, params, json_data, files)
        if data:
            return data

    def __search(self, query, endpoint, **kwargs):
        return self._prepare_request(quote("/".join([self.version, "search", query])), **kwargs)

    def synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/synscan/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of the search about synscans.
        """
        return self._prepare_request("/".join([self.version, "synscan", ip]), method="get")

    def summary_ip(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/ip/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request("/".join([self.version, "summary/ip", ip]), method="get")

    def summary_domain(self, domain):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/domain/<domain>

        :param domain: domain
        :type domain: str
        :returns: dict -- a dictionary containing the results of the summary of domain.
        """
        return self._prepare_request("/".join([self.version, "summary/domain", domain]), method="get")

    def summary_hostname(self, hostname):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/hostname/<hostname>

        :param hostname: hostname
        :type hostname: str
        :returns: dict -- a dictionary containing the results of the summary of hostname.
        """
        return self._prepare_request("/".join([self.version, "summary/hostname", hostname]), method="get")

    def simple_geoloc(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/geoloc/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of synscan of IP
        """
        return self._prepare_request("/".join([self.version, "simple/geoloc", ip]), method="get")

    def simple_geoloc_best(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/geoloc/best<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of geoloc of IP
        """
        return self._prepare_request("/".join([self.version, "simple/geoloc/best", ip]), method="get")

    def simple_inetnum(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/inetnum/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of inetnum of IP
        """
        return self._prepare_request("/".join([self.version, "simple/inetnum", ip]), method="get")

    def simple_inetnum_best(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/inetnum/best<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of intenum of IP
        """
        return self._prepare_request("/".join([self.version, "simple/inetnum/best", ip]), method="get")

    def simple_threatlist_best(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/threatlist/best<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of threatlist with best API of IP
        """
        return self._prepare_request("/".join([self.version, "simple/threatlist/best", ip]), method="get")

    def simple_pastries(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/pastries/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of pastries of IP
        """
        return self._prepare_request("/".join([self.version, "simple/pastries", ip]), method="get")

    def simple_resolver(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/resolver/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of resolver of IP
        """
        return self._prepare_request("/".join([self.version, "simple/resolver", ip]), method="get")

    def simple_sniffer(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/sniffer/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of sniffer of IP
        """
        return self._prepare_request("/".join([self.version, "simple/sniffer", ip]), method="get")

    def simple_synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/synscan/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of synscan of IP
        """
        return self._prepare_request("/".join([self.version, "simple/synscan", ip]), method="get")

    def simple_threatlist(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/threatlist/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of threatlist of IP
        """
        return self._prepare_request("/".join([self.version, "simple/threatlist", ip]), method="get")

    def simple_topsite(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/topsite/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of topsite of IP
        """
        return self._prepare_request("/".join([self.version, "simple/topsite", ip]), method="get")

    def simple_vulnscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/vulnscan/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of vulnscan of IP
        """
        return self._prepare_request("/".join([self.version, "simple/vulnscan", ip]), method="get")

    def simple_onionshot(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/onionshot/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of onionshot of IP
        """
        return self._prepare_request("/".join([self.version, "simple/onionshot", ip]), method="get")

    def simple_datashot(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/datashot/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of datashot of IP
        """
        return self._prepare_request("/".join([self.version, "simple/datashot", ip]), method="get")

    def simple_ctl(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/ctl/{<IP>,<str}

        :param data: domain or hostname
        :type data: str
        :returns: dict -- a dictionary containing Information on ctl on domain or hostname
        """
        return self._prepare_request("/".join([self.version, "simple/ctl", data]), method="get")

    def simple_onionscan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/onionscan/{<IP>,<str}

        :param data: data or hostname
        :type data: str
        :returns: dict -- a dictionary containing Information onionscan on domain or hostname
        """
        return self._prepare_request("/".join([self.version, "simple/onionscan", data]), method="get")

    def simple_datascan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/datascan/{<IP>,<str}

        :param data: IP or hostname
        :type data: str
        :returns: dict -- a dictionary containing Information on datascan on IP or hostname
        """
        return self._prepare_request("/".join([self.version, "simple/datascan", data]), method="get")

    def simple_datascan_datamd5(self, data_md5):
        """Call API Onyphe https://www.onyphe.io/api/v2/datascan/datamd5/<data_md5>

        :param data_md5: category of information we have for the given domain or hostname
        :type data_md5: str
        :returns: dict -- a dictionary containing Information onionscan on domain or hostname
        """
        return self._prepare_request("/".join([self.version, "simple/datascan/datamd5", data_md5]), method="get")

    def simple_resolver_forward(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/resolver/forward/<IP>
        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of forward of IP
        """
        return self.__resolver(ip, "forward")

    def simple_resolver_reverse(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/resolver/reverse/<IP>

        :param ip: IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of reverse of IP
        """
        return self.__resolver(ip, "reverse")

    def __resolver(self, ip, type_resolv):
        return self._prepare_request(
            "/".join([self.version, "simple/resolver/%s" % type_resolv, ip]),
            method="get",
        )

    def search(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example product:Apache port:443 os:Windows.
        :type query: str
        :return: dict -- a dictionary with result
        """
        kwargs["method"] = "get"
        return self.__search(query, "datascan", **kwargs)

    def alert_list(self):
        """Call API Onyphe https://www.onyphe.io/api/v2/alert/list

        :return: dict -- a dictionary with result
        """
        return self._prepare_request("/".join([self.version, "alert/list"]), method="get")

    def add_alert(self, query, name, email):
        """Call API Onyphe https://www.onyphe.io/api/v2/alert/add
         :param query: query language onyphe
         :type query: str
         :param name: name of alert
         :type name: str
         :param email: email to receive alerts
         :type email: str
        :return: dict -- a dictionary with result
        """
        if query and name and email:
            data = {"query": query, "name": name, "email": email}

            return self._prepare_request("/".join([self.version, "alert/add"]), method="post", json_data=data)
        else:
            raise ParamError("Parameters Invalid")

    def del_alert(self, id_alert):
        """Call API Onyphe https://www.onyphe.io/api/v2/alert/del

        :param id_alert: id of alert to delete
        :type id_alert: str
        :return: dict -- a dictionary with result
        """
        if id_alert:
            return self._prepare_request("/".join([self.version, "alert/del", id_alert]), method="post")
        else:
            raise ParamError("Parameter Invalid")

    def bulk_summary_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/summary/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/summary/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_summary_domain(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/summary/domain

        :param path: path of the files with domains
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/summary/domain"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_summary_hostname(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/summary/hostname

        :param path: path of the files with hostnames
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/summary/hostname"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_ctl_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/ctl/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/clt/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_datascan_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/datascan/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/datascan/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_datashot_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/datashot/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/datashot/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_geoloc_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/geoloc/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/geoloc/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_inetnum_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/inetnum/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/inetenum/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_pastries_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/pastries/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/pastries/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_resolver_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/resolver/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/resolver/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_sniffer_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/sniffer/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/sniffer/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_synscan_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/synscan/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/synscan/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_threatlist_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/threatlist/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/threatlist/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_topsite_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/topsite/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/topsite/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_vulnscan_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/vulnscan/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/vulnscan/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def bulk_simple_whois_ip(self, path):
        """Call API Onyphe https://www.onyphe.io/api/v2/bulk/simple/whois/ip

        :param path: path of the files with IPs
        :type path:str
        :return: dict -- a dictionary with result
        """
        if os.path.isfile(path):

            file_iocs = open(path, "rb")
            for line in self._prepare_request(
                "/".join([self.version, "bulk/simple/whois/ip"]),
                method="post",
                files=file_iocs,
            ).iter_lines():
                yield json.loads(line.decode("utf-8"))

        else:
            raise ParamError("%s is no a file" % path)

    def export(self, query):
        """Call API Onyphe https://www.onyphe.io/api/v2/export/
        :param query: example: category:datascan product:Nginx protocol:http os:Windows tls:true
        :type query:str
        :return: dict -- a dictionary with result
        """
        uri = quote("/".join([self.version, "export", query]))
        params = {"apikey": self.api_key}
        self._choose_url(uri)
        s = requests.Session()
        with s.get(self.url, params=params, stream=True) as r:
            for line in r.iter_lines():
                yield line
