import json
import logging
import sys
import time

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("urlscan")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

moduleinfo = {
    "version": "0.2",
    "author": "Dave Johnson",
    "description": "An expansion module to query urlscan.io.",
    "module-type": ["expansion"],
    "name": "URLScan Lookup",
    "logo": "urlscan.jpg",
    "requirements": ["An access to the urlscan.io API"],
    "features": (
        "This module takes a MISP attribute as input and queries urlscan.io with it.\n\nThe scan result is returned"
        " as the objects it describes - the url and the domain-ip it resolved to, where it is hosted, the certificate"
        " it presented, the screenshot urlscan took and any verdict against it - rather than as a flat list of"
        " attributes that drops the relationships between them."
    ),
    "references": ["https://urlscan.io/"],
    "input": "A domain, hostname or url attribute.",
    "output": "url, domain-ip, geolocation, asn, x509, image and reputation objects describing the scan.",
}

moduleconfig = ["apikey"]
misperrors = {"error": "Error"}
mispattributes = {
    "input": ["hostname", "domain", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}

# Page URLs whose wording gives the brand a phishing page is imitating.
_PHISHING_THEMES = (
    ("office", "Office"),
    ("o365", "O365"),
    ("0365", "O365"),
    ("microsoft", "Microsoft"),
    ("paypal", "PayPal"),
    ("onedrive", "OneDrive"),
    ("docusign", "DocuSign"),
)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "Urlscan apikey is missing"
        return misperrors

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    client = urlscanAPI(request["config"]["apikey"])
    try:
        result = client.search_url(attribute["value"])
    except Exception as e:
        misperrors["error"] = str(e)
        return misperrors

    failure = _unreachable(result)
    if failure:
        misperrors["error"] = failure
        return misperrors

    parser = UrlscanParser(attribute)
    parser.parse(result)
    return parser.get_results()


def _unreachable(result):
    """The scan failing to load the page at all, rather than loading it and
    having nothing to say about it."""
    for request in (result.get("data") or {}).get("requests") or []:
        failed = (request.get("response") or {}).get("failed") or {}
        error = failed.get("errorText")
        if error and error not in ("net::ERR_ABORTED", "net::ERR_FAILED", "net::ERR_QUIC_PROTOCOL_ERROR"):
            return f"Domain could not be resolved: {error}"
    return None


def _threat_types(result):
    matches = ((result.get("meta") or {}).get("processors") or {}).get("gsb", {}).get("data", {}).get("matches") or []
    return sorted({match["threatType"] for match in matches if match.get("threatType")})


def _phishing_themes(result):
    themes = set()
    for url in (result.get("lists") or {}).get("urls") or []:
        url = url.lower()
        for needle, brand in _PHISHING_THEMES:
            if needle in url:
                themes.add(brand)
    return sorted(themes)


class UrlscanParser:
    """One object per thing urlscan describes, with the relationships between
    them kept: the url is hosted on the domain-ip, which is in the geolocation
    and announced by the asn."""

    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.input_attribute = MISPAttribute()
        self.input_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.input_attribute)

    def _add(self, misp_object, referenced=None, relationship="related-to"):
        misp_object.add_reference(self.input_attribute.uuid, "related-to")
        if referenced is not None:
            misp_object.add_reference(referenced.uuid, relationship)
        self.misp_event.add_object(misp_object)
        return misp_object

    def parse(self, result):
        page = result.get("page") or {}
        task = result.get("task") or {}

        url_object = None
        scanned_url = task.get("url") or page.get("url")
        if scanned_url:
            url_object = MISPObject("url")
            url_object.add_attribute("url", scanned_url)
            if page.get("domain"):
                url_object.add_attribute("domain", page["domain"])
            if page.get("ip"):
                url_object.add_attribute("ip", page["ip"])
            # The url template has one text relation and no home for a page
            # title or a server banner, so both are labelled inside it.
            notes = [
                f"{label}: {value}"
                for label, value in (("title", page.get("title")), ("server", page.get("server")))
                if value
            ]
            if notes:
                url_object.add_attribute("text", "; ".join(notes))
            self._add(url_object)

        domain_ip = None
        if page.get("domain") or page.get("ip"):
            domain_ip = MISPObject("domain-ip")
            if page.get("domain"):
                domain_ip.add_attribute("domain", page["domain"])
            if page.get("ip"):
                domain_ip.add_attribute("ip", page["ip"])
            if page.get("ptr"):
                domain_ip.add_attribute("hostname", page["ptr"])
            self._add(domain_ip, referenced=url_object, relationship="resolves-to")

        if page.get("country") or page.get("city"):
            geolocation = MISPObject("geolocation")
            if page.get("country"):
                geolocation.add_attribute("countrycode", page["country"])
            if page.get("city"):
                geolocation.add_attribute("city", page["city"])
            self._add(geolocation, referenced=domain_ip)

        if page.get("asn"):
            asn = MISPObject("asn")
            asn.add_attribute("asn", page["asn"])
            if page.get("asnname"):
                asn.add_attribute("organization", page["asnname"])
            self._add(asn, referenced=domain_ip)

        if page.get("tlsIssuer"):
            x509 = MISPObject("x509")
            x509.add_attribute("issuer", page["tlsIssuer"])
            self._add(x509, referenced=url_object)

        if task.get("screenshotURL"):
            image = MISPObject("image")
            image.add_attribute("link", task["screenshotURL"])
            if scanned_url:
                image.add_attribute("url", scanned_url)
            self._add(image, referenced=url_object)

        self._parse_verdict(result, task, url_object)

    def _parse_verdict(self, result, task, url_object):
        threat_types = _threat_types(result)
        themes = _phishing_themes(result)
        malicious = (result.get("stats") or {}).get("malicious")
        if not (threat_types or themes or malicious):
            return
        # Typed explicitly, since pymisp does not bundle the reputation
        # template yet.
        reputation = MISPObject("reputation")
        reputation.add_attribute("classification", **{"type": "text", "value": "malicious"})
        reputation.add_attribute("source", **{"type": "text", "value": "urlscan.io"})
        if malicious:
            reputation.add_attribute("score", **{"type": "float", "value": float(malicious)})
        notes = []
        if threat_types:
            notes.append("Google Safe Browsing: " + ", ".join(threat_types))
        if themes:
            notes.append("possible phishing themes: " + ", ".join(themes))
        if notes:
            reputation.add_attribute("text", **{"type": "text", "value": "; ".join(notes)})
        if task.get("reportURL"):
            reputation.add_attribute("link", **{"type": "link", "value": task["reportURL"]})
        self._add(reputation, referenced=url_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


class urlscanAPI:
    def __init__(self, apikey=None, uuid=None):
        self.key = apikey
        self.uuid = uuid

    def request(self, query):
        log.debug("From request function with the parameter: " + query)
        payload = {"url": query}
        headers = {
            "API-Key": self.key,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
        }

        # Troubleshooting problems with initial search request
        log.debug("PAYLOAD: " + json.dumps(payload))
        log.debug("HEADERS: " + json.dumps(headers))

        search_url_string = "https://urlscan.io/api/v1/scan/"
        response = requests.request("POST", search_url_string, data=json.dumps(payload), headers=headers)

        # HTTP 400 - Bad Request
        if response.status_code == 400:
            raise Exception("HTTP Error 400 - Bad Request")

        # HTTP 404 - Not found
        if response.status_code == 404:
            raise Exception("HTTP Error 404 - These are not the droids you're looking for")

        # Any other status code
        if response.status_code != 200:
            raise Exception("HTTP Error " + str(response.status_code))

        if response.text:
            response = json.loads(response.content.decode("utf-8"))
            time.sleep(3)
            self.uuid = response["uuid"]

            # Strings for to check for errors on the results page
            # Null response string for any unavailable resources
            null_response_string = '"status": 404'
            # Redirect string accounting for 301/302/303/307/308 status codes
            redirect_string = '"status": 30'
            # Normal response string with 200 status code
            normal_response_string = '"status": 200'

            results_url_string = "https://urlscan.io/api/v1/result/" + self.uuid
            log.debug("Results URL: " + results_url_string)

            # Need to wait for results to process and check if they are valid
            tries = 10
            while tries >= 0:
                results = requests.request("GET", results_url_string)
                log.debug("Made a GET request")
                results = results.content.decode("utf-8")
                # checking if there is a 404 status code and no available resources
                if (
                    null_response_string in results
                    and redirect_string not in results
                    and normal_response_string not in results
                ):
                    log.debug("Results not processed. Please check again later.")
                    time.sleep(3)
                    tries -= 1
                else:
                    return json.loads(results)

            raise Exception("Results contained a 404 status error and could not be processed.")

    def search_url(self, query):
        log.debug("From search_url with parameter: " + query)
        return self.request(query)
