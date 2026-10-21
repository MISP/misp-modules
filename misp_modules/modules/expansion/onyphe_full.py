# -*- coding: utf-8 -*-

import base64
import ipaddress
import json
import re
import time
from pathlib import Path

from pymisp import MISPEvent, MISPObject
from pyonyphe import Onyphe as SDKOnyphe
from pyonyphe import OnypheError

misperrors = {"error": "Error"}

mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "hostname",
        "domain",
        "url",
        "cpe",
        "x509-fingerprint-sha256",
        "x509-fingerprint-sha1",
        "x509-fingerprint-md5",
    ],
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url", "port", "comment"],
    "format": "misp_standard",
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "3",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a full query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Full Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["pyonyphe python library, version 3.1.0 or later", "An access to the Onyphe API (apikey)"],
    "features": (
        "Searches the layered ctiscan/ctiurl and flat riskscan/vulnscan/datascan models, plus legacy CTI categories. "
        "Returns observed services, endpoints, certificates and CVE identifiers with source verdicts and JSON. "
        "Subscription-denied categories are reported as partial results. Search covers 30 days by default and "
        "is bounded to 10,000 results per category. Install the bundled onyphe-service template in MISP."
    ),
    "references": [
        "https://www.onyphe.io/",
        "https://github.com/onyphe/pyonyphe",
        "https://github.com/onyphe/material/tree/master/openapi",
    ],
    "input": "An IP, domain, hostname, URL, CPE or X.509 fingerprint MISP attribute.",
    "output": "MISP attributes and objects fetched from the Onyphe queries.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "limit", "categories", "timeout", "since"]

IP_TYPES = ("ip-src", "ip-dst")

# categories queried for an IP address and for a domain / hostname
IP_CATEGORIES = ("ctiscan", "ctiurl", "riskscan", "vulnscan", "datascan", "resolver", "ctl", "pastries", "threatlist")
ASSET_CATEGORIES = ("riskscan", "vulnscan", "datascan", "resolver", "ctl", "pastries", "threatlist")
LAYERED_CATEGORIES = ("ctiscan", "ctiurl")
SERVICE_CATEGORIES = (*LAYERED_CATEGORIES, "datascan", "vulnscan", "riskscan")
DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "onyphe"

# results fetched per category, the Search API pages at 10000 anyway
DEFAULT_LIMIT = 100
PAGE_SIZE = 100

SKIPPED_PREFIX = "Onyphe categories not returned: "


def as_list(value):
    """ONYPHE returns either a scalar or a list depending on the document, normalise both."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_routable(value):
    """Reject private, loopback, link-local, multicast and otherwise reserved addresses.

    Pastes routinely contain configuration samples, so ONYPHE extracts 127.0.0.1, RFC1918
    ranges or 224.0.0.0 from them. Those are noise in a MISP event, not indicators.

    The checks are spelled out rather than delegated to `is_global`: multicast is not part of
    the private ranges, so `is_global` answers True for 224.0.0.1, and the exact semantics of
    `is_global` have moved across Python versions.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def looks_like_host(value):
    """Cheap sanity check for names mined from the free text of a paste."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(value) and "." in value and not any(char in value for char in " \t/:@")


class Onyphe(SDKOnyphe):
    """Pace Search pages and category requests to the documented one request per second."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._last_search = None

    def search(self, *args, **kwargs):
        if self._last_search is not None:
            delay = 1 - (time.monotonic() - self._last_search)
            if delay > 0:
                time.sleep(delay)
        self._last_search = time.monotonic()
        return super().search(*args, **kwargs)


class OnypheFullClient:

    def __init__(self, api_key, attribute, limit=DEFAULT_LIMIT, categories=None, timeout=30, since=None):
        self.onyphe_client = Onyphe(api_key=api_key, timeout=timeout)
        self.attribute = attribute
        self.limit = max(1, min(limit, 10000))
        self.categories = categories
        self.since = since
        self.objects = {}
        self.misp_event = MISPEvent()
        source = self.misp_event.add_attribute(**attribute)
        self.attribute = source.to_dict()
        self.skipped = []
        self.__seen = set()

    def close(self):
        self.onyphe_client.close()

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if key in event}
        return results

    # -- querying -----------------------------------------------------------

    def get_query_onyphe(self):
        defaults = IP_CATEGORIES if self.attribute["type"] in IP_TYPES else ASSET_CATEGORIES
        if self.attribute["type"] == "hostname":
            defaults = (*LAYERED_CATEGORIES, *defaults)
        if self.attribute["type"] == "url":
            defaults = ("ctiurl",)
        elif self.attribute["type"] in (
            "cpe",
            "x509-fingerprint-sha256",
            "x509-fingerprint-sha1",
            "x509-fingerprint-md5",
        ):
            defaults = LAYERED_CATEGORIES
        categories = self.categories or defaults
        if self.attribute["type"] == "domain" and any(c in LAYERED_CATEGORIES for c in categories):
            raise ValueError("ctiscan/ctiurl require an IP or hostname; use riskscan/vulnscan for domains")
        parsers = {
            "ctl": self.parse_certificate,
            "pastries": self.__parse_pastries,
            "resolver": self.__parse_resolver,
            "threatlist": self.__parse_threatlist,
        }
        for category in categories:
            try:
                count = 0
                for hit in self.__search(category):
                    if category in SERVICE_CATEGORIES:
                        self.__parse_service(hit, category)
                    else:
                        parsers[category](hit)
                    count += 1
                if count >= self.limit:
                    self.__add_attribute(
                        "comment",
                        f"Onyphe {category} reached the {self.limit} result limit; more records may exist.",
                        to_ids=False,
                    )
            except OnypheError as e:
                # Only subscription denials are skippable. Authentication, exhausted credits,
                # rate limits and network failures must not look like a successful empty lookup.
                payload = getattr(e, "payload", {})
                if payload.get("error") == 13 or (payload.get("error") == 12 and "access denied:" in str(e).lower()):
                    self.skipped.append(f"{category}: {e}")
                else:
                    raise
        self.__report_skipped()

    def __search(self, category):
        value = json.dumps(self.attribute["value"], ensure_ascii=False)
        if category in LAYERED_CATEGORIES:
            if self.attribute["type"] in IP_TYPES:
                term = f"ip.dest:{value}"
            elif self.attribute["type"] == "url":
                term = f"http.url:{value}"
            elif self.attribute["type"] == "cpe":
                term = f"component.cpe:{value}"
            elif self.attribute["type"].startswith("x509-fingerprint-"):
                term = f"cert.fingerprint.{self.attribute['type'].removeprefix('x509-fingerprint-')}:{value}"
            elif self.attribute["type"] == "hostname":
                term = f"( ?dns.hostname:{value} ?dns.forward.hostname:{value} ?dns.reverse.hostname:{value} )"
            else:
                raise ValueError("ctiscan/ctiurl require an IP or hostname; use riskscan/vulnscan for domains")
            fields = ",".join(
                (
                    "ip",
                    "tcp",
                    "app",
                    "component",
                    "http",
                    "html",
                    "cert",
                    "dns",
                    "favicon",
                    "tag",
                    "source",
                    "seen_date",
                    "@category",
                    "@timestamp",
                    "trackquery",
                )
            )
        else:
            field = "ip" if self.attribute["type"] in IP_TYPES else self.attribute["type"]
            if field.startswith("x509-fingerprint-"):
                field = "fingerprint." + field.removeprefix("x509-fingerprint-")
            term = f"{field}:{value}"
            fields = ",".join(
                (
                    "ip",
                    "ipv6",
                    "port",
                    "transport",
                    "protocol",
                    "hostname",
                    "domain",
                    "url",
                    "asn",
                    "organization",
                    "country",
                    "subnet",
                    "product",
                    "productvendor",
                    "productversion",
                    "cpe",
                    "cve",
                    "tag",
                    "data",
                    "device",
                    "app",
                    "tls",
                    "status",
                    "issuer",
                    "subject",
                    "serial",
                    "fingerprint",
                    "signature",
                    "publickey",
                    "validity",
                    "seen_date",
                    "@category",
                    "@timestamp",
                    "source",
                    "trackquery",
                )
            )
        query = f"category:{category} {term}"
        if self.since:
            query += f" -since:{self.since}"
        if category in SERVICE_CATEGORIES:
            query += f" -fields:{fields}"
        return self.onyphe_client.search_iter(query, size=min(PAGE_SIZE, self.limit), max_results=self.limit)

    def __report_skipped(self):
        """Surface the categories that were dropped instead of letting them vanish.

        A key not entitled to vulnscan produces an event that simply holds no vulnerability,
        with nothing telling the analyst whether the asset is clean or the query incomplete.
        """
        if not self.skipped:
            return
        self.__add_attribute(
            "comment",
            SKIPPED_PREFIX + "; ".join(self.skipped),
            category="Other",
            to_ids=False,
            comment="These Onyphe categories were not queried successfully, the event is partial",
        )

    # -- helpers ------------------------------------------------------------

    def __already(self, attribute_type, value):
        return ("attribute", attribute_type, str(value)) in self.__seen

    def __add_attribute(self, attribute_type, value, **kwargs):
        """Add an event attribute once, ONYPHE repeats the same observation across documents."""
        if not value:
            return
        key = ("attribute", attribute_type, str(value))
        if key in self.__seen:
            return
        self.__seen.add(key)
        kwargs.setdefault("to_ids", False)
        self.misp_event.add_attribute(attribute_type, value, **kwargs)

    def __add_object(self, misp_object, signature):
        key = ("object", misp_object.name, signature)
        if key in self.objects:
            return self.objects[key]
        # All derived observations are enrichment context, not detection rules.
        for attribute in misp_object.attributes:
            attribute.to_ids = False
        misp_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(misp_object)
        self.objects[key] = misp_object
        return misp_object

    @staticmethod
    def __link(obj, uuid, relationship):
        if not any(r.referenced_uuid == uuid and r.relationship_type == relationship for r in obj.references):
            obj.add_reference(uuid, relationship)

    @staticmethod
    def __add_values(obj, relation, values):
        for value in as_list(values):
            if value is not None and value != "" and not isinstance(value, (dict, list)):
                if not any(a.object_relation == relation and str(a.value) == str(value) for a in obj.attributes):
                    obj.add_attribute(relation, value=value, to_ids=False)

    def __parse_service(self, hit, category):
        layered = category in LAYERED_CATEGORIES
        network = hit.get("ip", {}) if layered else hit
        app = hit.get("app") or {}
        component = (hit.get("component") or {}) if layered else hit
        cves = as_list(component.get("cve"))
        dns = hit.get("dns") or {}
        ips = network.get("dest") if layered else as_list(hit.get("ip")) + as_list(hit.get("ipv6"))
        port = (hit.get("tcp") or {}).get("dest") if layered else hit.get("port")
        hostnames = (
            list(
                dict.fromkeys(
                    as_list(dns.get("hostname"))
                    + as_list((dns.get("forward") or {}).get("hostname"))
                    + as_list((dns.get("reverse") or {}).get("hostname"))
                )
            )
            if layered
            else hit.get("hostname")
        )
        url = (hit.get("http") or {}).get("url") if layered else hit.get("url")
        if not any((ips, hostnames, hit.get("domain") if not layered else None, url)):
            return
        service = MISPObject("onyphe-service", strict=True, misp_objects_path_custom=DATA_PATH)
        values = {
            "category": category,
            "ip": ips,
            "port": port,
            "hostname": hostnames,
            "domain": hit.get("domain") if not layered else None,
            "transport": app.get("transport") if layered else hit.get("transport"),
            "protocol": app.get("protocol") if layered else hit.get("protocol"),
            "device": app.get("device") if layered else (hit.get("device") or {}).get("class"),
            "seen-date": hit.get("seen_date"),
            "timestamp": hit.get("@timestamp"),
            "source": hit.get("source"),
            "tag": hit.get("tag"),
            "cve": cves,
            "cpe": component.get("cpe"),
            "product": component.get("product"),
            "vendor": component.get("vendor") if layered else hit.get("productvendor"),
            "version": component.get("version") if layered else hit.get("productversion"),
            "url": url,
            "http-status": (hit.get("http") or {}).get("code") if layered else hit.get("status"),
            "http-title": (
                ((hit.get("html") or {}).get("title") or {}).get("raw")
                if layered
                else (app.get("http") or {}).get("title")
            ),
            "response-md5": (app.get("data") or {}).get("md5") if layered else None,
            "response-length": (app.get("data") or {}).get("length") if layered else None,
            "trackquery": hit.get("trackquery"),
        }
        for field in ("asn", "organization", "country", "subnet", "netname"):
            values[field] = network.get(field)
        for relation, value in values.items():
            self.__add_values(service, relation, value)
        tls = app.get("tls") if layered else hit.get("tls")
        for value in as_list(tls):
            if str(value).lower() in ("true", "false"):
                self.__add_values(service, "tls", str(value).lower() == "true")
        raw = json.dumps(hit, sort_keys=True, ensure_ascii=False)
        service.add_attribute(
            "raw-json", value="onyphe-observation.json", data=base64.b64encode(raw.encode()).decode(), to_ids=False
        )
        service = self.__add_object(service, raw)
        endpoint_hit = {
            "ip": ips,
            "port": port,
            "hostname": hostnames,
            "domain": values["domain"],
            "transport": values["transport"],
            "asn": network.get("asn"),
            "country": network.get("country"),
            "seen_date": hit.get("seen_date"),
        }
        # The generic endpoint carries network context; the service retains the application model.
        endpoint = self.__parse_datascan(endpoint_hit)
        if endpoint:
            self.__link(service, endpoint.uuid, "observed-on")
        certificate = self.parse_certificate(hit.get("cert") or {}) if layered else self.parse_certificate(hit)
        if certificate:
            self.__link(service, certificate.uuid, "presents")
        tags = as_list(hit.get("tag"))
        positive = category == "riskscan" or (
            "vulnerable" in tags and not any(t.startswith("notvulnerable") for t in tags)
        )
        for cve in cves:
            vulnerability = self.__add_vulnerability(cve)
            # Version inference, uncertain and negative verdicts stay as source tags, not affects assertions.
            self.__link(vulnerability, service.uuid, "affects" if positive else "related-to")

    # -- parsers ------------------------------------------------------------

    def __parse_datascan(self, hit):
        misp_object = MISPObject("ip-port")
        anchored = False

        for ip in as_list(hit.get("ip")):
            misp_object.add_attribute("ip", ip)
            anchored = True
        for domain in as_list(hit.get("domain")):
            misp_object.add_attribute("domain", domain)
            anchored = True
        for hostname in as_list(hit.get("hostname")):
            misp_object.add_attribute("hostname", hostname)
            anchored = True
        if hit.get("port"):
            self.__add_values(misp_object, "dst-port", hit["port"])
            anchored = True

        if not anchored:
            return

        if hit.get("transport"):
            misp_object.add_attribute("protocol", as_list(hit["transport"])[0])
        if hit.get("asn"):
            self.__add_values(misp_object, "AS", hit["asn"])
        if hit.get("country"):
            misp_object.add_attribute("country-code", as_list(hit["country"])[0])
        if hit.get("seen_date"):
            misp_object.add_attribute("last-seen", as_list(hit["seen_date"])[0])

        signature = json.dumps(hit, sort_keys=True)
        misp_object = self.__add_object(misp_object, signature)
        return misp_object

    def __parse_resolver(self, hit):
        for ip in as_list(hit.get("ip")):
            self.__add_attribute("ip-dst", ip, category="Network activity")
        for domain in as_list(hit.get("domain")):
            self.__add_attribute("domain", domain, category="Network activity")
        # `reverse` and `forward` hold fully qualified names, not registrable domains
        for hostname in as_list(hit.get("hostname")) + as_list(hit.get("reverse")) + as_list(hit.get("forward")):
            if not self.__already("domain", hostname):
                self.__add_attribute("hostname", hostname, category="Network activity")

        for ip in as_list(hit.get("ip")):
            for name in as_list(hit.get("domain")):
                misp_object = MISPObject("domain-ip")
                misp_object.add_attribute("ip", ip)
                misp_object.add_attribute("domain", name)
                if hit.get("type"):
                    misp_object.add_attribute("text", f"{hit['type']} record seen by Onyphe")
                self.__add_object(misp_object, f"{ip}|{name}")

    def __parse_pastries(self, hit):
        # everything mined from the text of a paste is context, not an observation of the
        # queried asset: it is added with to_ids disabled so it never reaches a detection feed
        if hit.get("source") == "pastebin" and hit.get("key"):
            self.__add_attribute(
                "url",
                f"https://pastebin.com/raw/{hit['key']}",
                category="External analysis",
                to_ids=False,
                comment=f"Paste where {self.attribute['value']} was found by Onyphe",
            )

        comment = "Found in a paste indexed by Onyphe"
        for domain in as_list(hit.get("domain")):
            if looks_like_host(domain):
                self.__add_attribute("domain", domain, category="Network activity", to_ids=False, comment=comment)
        for hostname in as_list(hit.get("hostname")):
            if looks_like_host(hostname) and not self.__already("domain", hostname):
                self.__add_attribute("hostname", hostname, category="Network activity", to_ids=False, comment=comment)
        for ip in as_list(hit.get("ip")):
            if is_routable(ip):
                self.__add_attribute("ip-dst", ip, category="Network activity", to_ids=False, comment=comment)

    def __parse_threatlist(self, hit):
        threatlist = hit.get("threatlist")
        if not threatlist:
            return
        self.__add_attribute(
            "comment",
            f"seen {hit.get('seen_date', 'at an unknown date')} on {threatlist}",
            category="Other",
            comment=f"{self.attribute['value']} is present in an Onyphe threatlist",
        )

    def parse_certificate(self, hit):
        def scalar(value):
            values = [v for v in as_list(value) if v is not None and v != "" and not isinstance(v, (dict, list))]
            return values[0] if len(values) == 1 else None

        fingerprint = hit.get("fingerprint") or {}
        if not (fingerprint or hit.get("serial") or hit.get("issuer")):
            return

        misp_object = MISPObject("x509")

        # note: the x509 `ip` relation is a Subject Alternative Name, not the host serving the
        # certificate -- the queried value is tied to the object through its reference instead.
        serial = hit.get("serial")
        if isinstance(serial, dict):
            number = scalar(serial.get("hex"))
            if number is None:
                number = scalar(serial.get("num"))
        else:
            number = scalar(serial)
        if number is not None:
            misp_object.add_attribute("serial-number", number)

        for algorithm in ("md5", "sha1", "sha256"):
            if scalar(fingerprint.get(algorithm)):
                misp_object.add_attribute(f"x509-fingerprint-{algorithm}", scalar(fingerprint[algorithm]))

        algorithm = scalar((hit.get("signature") or {}).get("algorithm")) or ""
        value = ""
        if "sha256" in algorithm and "RSA" in algorithm:
            value = "SHA256_WITH_RSA_ENCRYPTION"
        elif "sha1" in algorithm and "RSA" in algorithm:
            value = "SHA1_WITH_RSA_ENCRYPTION"
        if value:
            misp_object.add_attribute("signature_algorithm", value)

        publickey = hit.get("publickey") or {}
        if scalar(publickey.get("algorithm")) is not None:
            misp_object.add_attribute("pubkey-info-algorithm", scalar(publickey["algorithm"]))
        if scalar(publickey.get("exponent")) is not None:
            misp_object.add_attribute("pubkey-info-exponent", scalar(publickey["exponent"]))
        if scalar(publickey.get("length")) is not None:
            misp_object.add_attribute("pubkey-info-size", scalar(publickey["length"]))

        issuer = (hit.get("issuer") or {}).get("commonname") or (hit.get("issuer") or {}).get("cn")
        if not issuer:
            issuer = (hit.get("issuer") or {}).get("o") or (hit.get("issuer") or {}).get("organization")
        if issuer:
            misp_object.add_attribute("issuer", ", ".join(map(str, as_list(issuer))))

        subject = (hit.get("subject") or {}).get("commonname") or (hit.get("subject") or {}).get("cn")
        if subject:
            misp_object.add_attribute("subject", ", ".join(map(str, as_list(subject))))

        validity = hit.get("validity") or {}
        if scalar(validity.get("notbefore")):
            misp_object.add_attribute("validity-not-before", scalar(validity["notbefore"]))
        if scalar(validity.get("notafter")):
            misp_object.add_attribute("validity-not-after", scalar(validity["notafter"]))

        for part in ("issuer", "subject"):
            source = hit.get(part) or {}
            for field, relation in (("o", "organization"), ("c", "country"), ("ou", "organizational-unit")):
                if source.get(field):
                    misp_object.add_attribute(f"{part}-{relation}", ", ".join(map(str, as_list(source[field]))))
        if not any(a.object_relation in misp_object._definition["requiredOneOf"] for a in misp_object.attributes):
            return None
        signature = json.dumps([(a.object_relation, str(a.value)) for a in misp_object.attributes])
        return self.__add_object(misp_object, signature)

    def __add_vulnerability(self, cve):
        misp_object = MISPObject("vulnerability")
        misp_object.add_attribute("id", cve)
        misp_object = self.__add_object(misp_object, cve)
        return misp_object


def handler(q=False):
    if not q:
        return False

    request = json.loads(q)

    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "Onyphe authentication is missing"
        return misperrors

    try:
        limit = int(request["config"].get("limit") or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT
    config = request["config"]
    categories = config.get("categories")
    if categories:
        categories = [c.strip() for c in categories.split(",") if c.strip()]
        if not categories or set(categories) - set(IP_CATEGORIES):
            return {"error": "Invalid Onyphe categories"}
    since = config.get("since") or None
    if since and not re.fullmatch(r"[1-9][0-9]*[hdwMy]", since):
        return {"error": "Invalid Onyphe since period (for example 7d, 1w or 7M)"}
    attribute = request.get("attribute") or {}
    if attribute.get("type") not in mispattributes["input"] or not isinstance(attribute.get("value"), str):
        return {"error": "Unsupported Onyphe input attribute"}
    onyphe_client = None
    try:
        timeout = float(config.get("timeout") or 30)
        if not 0 < timeout <= 300:
            raise ValueError("Onyphe timeout must be between 0 and 300 seconds")
        onyphe_client = OnypheFullClient(config["apikey"], attribute, limit, categories, timeout, since)
        onyphe_client.get_query_onyphe()
        return {"results": onyphe_client.get_results()}
    except (OnypheError, ValueError, TypeError) as e:
        return {"error": f"Onyphe error: {e}"}
    finally:
        if onyphe_client:
            onyphe_client.close()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
