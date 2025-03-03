import warnings

import requests
from dnstrails.exception import APIError

"""
dnstrails.api
~~~~~~~~~~~~~

This module implements the DNSTrail API.

:copyright: (c) 2018 - by Sebastien Larinier
"""


def deprecated(message):
    def deprecated_decorator(func):
        def deprecated_func(*args, **kwargs):
            warnings.warn(
                "{} is a deprecated function. {}".format(func.__name__, message),
                category=DeprecationWarning,
                stacklevel=2,
            )
            warnings.simplefilter("default", DeprecationWarning)
            return func(*args, **kwargs)

        return deprecated_func

    return deprecated_decorator


class DnsTrails:
    """Wrapper around the DNSTrail REST

    :param key: The DNSTrail API key that can be obtained from your account
    page (https://securitytrails.com/)
    :type key: str

    :param version Version of API
    """

    def __init__(self, api_key, version="v1"):
        self._key = api_key
        self.base_url = "https://api.securitytrails.com"
        self.version = version
        self._session = requests.Session()

        self.methods = {"get": self._session.get, "post": self._session.post}

    def _prepare_query(self, query, **kwargs):

        self._headers = {"apikey": self._key}
        self._payload = {}
        if "page" in kwargs:
            self._payload["page"] = kwargs.get("page")
        if "mask" in kwargs:
            self._payload["mask"] = kwargs.get("mask")

        self.data = {"filter": {k: v for k, v in kwargs.items() if k != "mask" and k != "page"}}

        self.url = "%s/%s/%s" % (self.base_url, self.version, "/".join(query))

    def _request(self, method="get"):

        data = None

        try:
            if method == "get":
                if not self._payload:
                    response = self.methods[method](self.url, headers=self._headers)
                else:

                    response = self.methods[method](self.url, headers=self._headers, params=self._payload)
            elif method == "post":
                self._headers["Content-type"] = "application/json"

                response = self.methods[method](
                    self.url,
                    headers=self._headers,
                    json=self.data,
                    params=self._payload,
                )

        except Exception as e:
            raise APIError("Unable to connect DNSTrail %s" % e)

        if response.status_code == requests.codes.NOT_FOUND:

            raise APIError("Page Not found %s" % self.url)
        elif response.status_code == requests.codes.FORBIDDEN:
            raise APIError("Access Forbidden")
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()["message"]
            except Exception as e:
                error = "Invalid API key %s" % e

            raise APIError(error)

        try:

            data = response.json()

        except Exception as e:
            raise APIError("Unable to parse JSON %s" % e)

        return data

    def _query(self, query, method="get", **kwargs):
        self._prepare_query(query, **kwargs)

        data = self._request(method=method)

        if data:
            return data
        else:
            raise APIError("Error API")

    def ping(self):
        """Call API Ping to test your API key and connectivity
        GET https://api.securitytrails.com/v1/ping
            :returns: dict -- status of connectivity

        """
        query = ["ping"]
        return self._query(query)

    def domain(self, domain):
        """Call API Get Domain information about a domain
            GET https://api.securitytrails.com/v1/domain/<domain>
        :param domain: fqdn for query
        :type: domain: str
        :return: dict -- a dictionary containing the result of the service on
        one domain
        """
        query = ["domain", domain]
        return self._query(query)

    def subdomains(self, domain):
        """Call API subdomains on one domain
        GET https://api.securitytrails.com/v1/domain/<domain>/subdomains
        :param domain: domain for query
        :return: dict -- a dictionary containing the list of subdomains
        """
        query = ["domain", domain, "subdomains"]

        return self._query(query)

    def tags(self, domain):
        """Call API tags for listing tags about a domain
        GET https://api.securitytrails.com/v1/domain/<domain>/tags
        :param domain: domain for query
        :type: domain: str
        :return: dict -- a dictionary containing the list of tags
        """
        query = ["domain", domain, "tags"]

        return self._query(query)

    def whois(self, domain):
        """Call API Whois on a domain
        GET https://api.securitytrails.com/v1/domain/<domain>/whois
        :param domain: domain for query
        :type domain: str
        :return: dict -- a dictionary containing the whois result of a domain
        """

        query = ["domain", domain, "whois"]

        return self._query(query)

    def history_dns_ipv4(self, domain, **kwargs):
        """Call API historical Ipv4 on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/a?page=<page>
        :param domain: domain for query
        :type domain: str
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the Ipv4 historical data
        """
        query = ["history", domain, "dns", "a"]

        return self._query(query, **kwargs)

    def history_dns_aaaa(self, domain, **kwargs):
        """Call API historical Ipv6 on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/aaaa?page=<page>
        :param domain: domain for query
        :type:domain
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the Ipv6 historical data
        """
        query = ["history", domain, "dns", "aaaa"]

        return self._query(query, **kwargs)

    def history_dns_mx(self, domain, **kwargs):
        """Call API historical mx on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/mx?page=<page>
        :param domain: domain for query
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the mx historical data
        """
        query = ["history", domain, "dns", "mx"]

        return self._query(query, **kwargs)

    def history_dns_ns(self, domain, **kwargs):
        """Call API historical mx on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/ns?page=<page>
        :param domain: domain for query
        :type domain: str
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the ns historical data
        """
        query = ["history", domain, "dns", "ns"]

        return self._query(query, **kwargs)

    def history_dns_soa(self, domain, **kwargs):
        """Call API historical mx on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/soa?page=<page>
        :param domain: domain for query
        :type domain: str
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the soa historical data
        """
        query = ["history", domain, "dns", "soa"]

        return self._query(query, **kwargs)

    def history_dns_txt(self, domain, **kwargs):
        """Call API historical txt on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/dns/txt?page=<page>
        :param domain: domain for query
        :type domain: str
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the txt historical data
        """
        query = ["history", domain, "dns", "txt"]

        return self._query(query, **kwargs)

    def history_whois(self, domain, **kwargs):
        """Call API historical whois on a domain
        GET https://api.securitytrails.com/v1/history/<domain>/whois?page=<page>
        :param domain: domain for query
        :type domain: str
        :param page:  number of page of the result
        :type page: int
        :return: dict -- a dictionary containing the whois historical data
        """

        query = ["history", domain, "whois"]

        return self._query(query, **kwargs)

    def explore_ip(self, ip, **kwargs):
        """Call API explore IP to have he neighbors in any given IP level range
        and essentially allows you to explore closeby IP addresses.
         GET  https://api.securitytrails.com/v1/explore/ip/ip?mask=<mask>
        :param ip: Ipv4 for query
        :type ip: str
        :param mask: mask of the block
        :type mask: int
        :return: dict -- a dictionary containing the neighboors of IP
        """
        query = ["explore", "ip", ip]

        return self._query(query, **kwargs)

    def searching_domains(self, **kwargs):
        """Call API searching domain
        POST https://api.securitytrails.com/v1/search/list?page=<page>
        :param page: page results
        :type page: int

        :param ipv4 (can include a network mask):
        :type ipv4: str

        :param ipv6:
        :type ipv6: str

        :param mx:
        :type ipv6: str

        :param ns:
        :type ns: str

        :param cname:
        :type cname: str

        :param subdomain:
        :type subdomain: str

        :param apex_domain:
        :type subdomain: str

        :param soa_email:
        :type soa_email: str

        :param tld:
        :type tld: str

        :param whois_email:
        :type whois_email: str

        :param whois_street1:
        :type whois_street1: str

        :param whois_street2:
        :type whois_street2: str

        :param whois_street3:
        :type whois_street3: str

        :param whois_street4:
        :type whois_street4: str

        :param whois_telephone:
        :type whois_telephone: str

        :param whois_postalCode:
        :type whois_postalCode: str

        :param whois_organization:
        :type whois_organization: str

        :param whois_name:
        :type whois_name: str

        :param whois_fax:
        :type whois_fax: str

        :param whois_city:
        :type whois_city: str

        :param keyword:
        :type keyword: str

        :return: dict -- a dictionary containing the results of domain searching
        """
        query = ["search", "list"]

        return self._query(query, method="post", **kwargs)

    @deprecated("a new implementation of stat will be developped")
    def search_stats(self, **kwargs):
        """Call API stats
        POST https://api.securitytrails.com/v1/search/list/stats

        :param ipv4 (can include a network mask):
        :type ipv4: str

        :param ipv6:
        :type ipv6: str

        :param mx:
        :type ipv6: str

        :param ns:
        :type ns: str

        :param cname:
        :type cname: str

        :param subdomain:
        :type subdomain: str

        :param apex_domain:
        :type subdomain: str

        :param soa_email:
        :type soa_email: str

        :param tld:
        :type tld: str

        :param whois_email:
        :type whois_email: str

        :param whois_street1:
        :type whois_street1: str

        :param whois_street2:
        :type whois_street2: str

        :param whois_street3:
        :type whois_street3: str

        :param whois_street4:
        :type whois_street4: str

        :param whois_telephone:
        :type whois_telephone: str

        :param whois_postalCode:
        :type whois_postalCode: str

        :param whois_organization:
        :type whois_organization: str

        :param whois_name:
        :type whois_name: str

        :param whois_fax:
        :type whois_fax: str

        :param whois_city:
        :type whois_city: str

        :param keyword:
        :type keyword: str

        :return: dict -- a dictionary containing the results of domain searching
        """
        query = ["search", "list", "stats"]

        return self._query(query, method="post", **kwargs)
