import json
import logging
from urllib.parse import urlparse

import vt
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["hostname", "domain", "ip-src", "ip-dst", "md5", "sha1", "sha256", "url"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "2",
    "author": "Christian Studer",
    "description": "Enrich observables with the VirusTotal v3 public API",
    "module-type": ["expansion", "hover"],
    "name": "VirusTotal Public API Lookup",
    "logo": "virustotal.png",
    "requirements": ["An access to the VirusTotal API (apikey)"],
    "features": (
        "New format of modules able to return attributes and objects.\n\nA module to take a MISP attribute as input and"
        " query the VirusTotal API to get additional data about it.\n\nCompared to the [more advanced VirusTotal"
        " expansion"
        " module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/virustotal.py), this"
        " module is made for VirusTotal users who have a low request rate limit.\n\nThus, it only queries the API once"
        " and returns the results that is parsed into MISP attributes and objects."
    ),
    "references": [
        "https://www.virustotal.com",
        "https://docs.virustotal.com/reference/overview",
    ],
    "input": "A domain, hostname, ip, url or hash (md5, sha1, sha256 or sha512) attribute.",
    "output": (
        "MISP attributes and objects resulting from the parsing of the VirusTotal report concerning the input"
        " attribute."
    ),
}

moduleconfig = [
    "apikey",
    "proxy_host",
    "proxy_port",
    "proxy_username",
    "proxy_password",
]

LOGGER = logging.getLogger("virus_total_public")
LOGGER.setLevel(logging.INFO)


DEFAULT_RESULTS_LIMIT = 10


class VirusTotalParser:
    def __init__(self, client: vt.Client, limit: int) -> None:
        self.client = client
        self.limit = limit or DEFAULT_RESULTS_LIMIT
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.parsed_objects = {}
        self.input_types_mapping = {
            "ip-src": self.parse_ip,
            "ip-dst": self.parse_ip,
            "domain": self.parse_domain,
            "hostname": self.parse_domain,
            "md5": self.parse_hash,
            "sha1": self.parse_hash,
            "sha256": self.parse_hash,
            "url": self.parse_url,
        }
        self.proxies = None

    @staticmethod
    def get_total_analysis(analysis: dict, known_distributors: dict = None) -> int:
        if not analysis:
            return 0
        count = sum([analysis["undetected"], analysis["suspicious"], analysis["harmless"]])
        return count if known_distributors else count + analysis["malicious"]

    def query_api(self, attribute: dict) -> None:
        self.attribute.from_dict(**attribute)
        self.input_types_mapping[self.attribute.type](self.attribute.value)

    def get_result(self) -> dict:
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def add_vt_report(self, report: vt.Object) -> str:
        analysis = report.get("last_analysis_stats")
        total = self.get_total_analysis(analysis, report.get("known_distributors"))
        permalink = f"https://www.virustotal.com/gui/{report.type}/{report.id}"

        vt_object = MISPObject("virustotal-report")
        vt_object.add_attribute("permalink", type="link", value=permalink)
        detection_ratio = f"{analysis['malicious']}/{total}" if analysis else "-/-"
        vt_object.add_attribute(
            "detection-ratio",
            type="text",
            value=detection_ratio,
            disable_correlation=True,
        )
        self.misp_event.add_object(**vt_object)
        return vt_object.uuid

    def create_misp_object(self, report: vt.Object) -> MISPObject:
        misp_object = None
        vt_uuid = self.add_vt_report(report)
        if report.type == "file":
            misp_object = MISPObject("file")
            for hash_type in (
                "md5",
                "sha1",
                "sha256",
                "tlsh",
                "vhash",
                "ssdeep",
                "imphash",
            ):
                misp_object.add_attribute(
                    **{
                        "type": hash_type,
                        "object_relation": hash_type,
                        "value": report.get(hash_type),
                    }
                )
        elif report.type == "domain":
            misp_object = MISPObject("domain-ip")
            misp_object.add_attribute("domain", type="domain", value=report.id)
        elif report.type == "ip_address":
            misp_object = MISPObject("domain-ip")
            misp_object.add_attribute("ip", type="ip-dst", value=report.id)
        elif report.type == "url":
            misp_object = MISPObject("url")
            misp_object.add_attribute("url", type="url", value=report.id)
        misp_object.add_reference(vt_uuid, "analyzed-with")
        return misp_object

    ################################################################################
    ####                         Main parsing functions                         #### # noqa
    ################################################################################

    def parse_domain(self, domain: str) -> str:
        domain_report = self.client.get_object(f"/domains/{domain}")

        # DOMAIN
        domain_object = self.create_misp_object(domain_report)

        # WHOIS
        if domain_report.whois:
            whois_object = MISPObject("whois")
            whois_object.add_attribute("text", type="text", value=domain_report.whois)
            self.misp_event.add_object(**whois_object)

        # SIBLINGS AND SUBDOMAINS
        for relationship_name, misp_name in [
            ("siblings", "sibling-of"),
            ("subdomains", "subdomain"),
        ]:
            rel_iterator = self.client.iterator(f"/domains/{domain_report.id}/{relationship_name}", limit=self.limit)
            for item in rel_iterator:
                attr = MISPAttribute()
                attr.from_dict(**dict(type="domain", value=item.id))
                self.misp_event.add_attribute(**attr)
                domain_object.add_reference(attr.uuid, misp_name)

        # RESOLUTIONS
        resolutions_iterator = self.client.iterator(f"/domains/{domain_report.id}/resolutions", limit=self.limit)
        for resolution in resolutions_iterator:
            domain_object.add_attribute("ip", type="ip-dst", value=resolution.ip_address)

        # COMMUNICATING AND REFERRER FILES
        for relationship_name, misp_name in [
            ("communicating_files", "communicates-with"),
            ("referrer_files", "referring"),
        ]:
            files_iterator = self.client.iterator(f"/domains/{domain_report.id}/{relationship_name}", limit=self.limit)
            for file in files_iterator:
                file_object = self.create_misp_object(file)
                file_object.add_reference(domain_object.uuid, misp_name)
                self.misp_event.add_object(**file_object)

        self.misp_event.add_object(**domain_object)
        return domain_object.uuid

    def parse_hash(self, file_hash: str) -> str:
        file_report = self.client.get_object(f"/files/{file_hash}")
        file_object = self.create_misp_object(file_report)

        # COMMUNICATING, DOWNLOADED AND REFERRER FILES
        for relationship_name, misp_name in [
            ("contacted_urls", "communicates-with"),
            ("contacted_domains", "communicates-with"),
            ("contacted_ips", "communicates-with"),
        ]:
            related_files_iterator = self.client.iterator(
                f"/files/{file_report.id}/{relationship_name}", limit=self.limit
            )
            for related_file in related_files_iterator:
                related_file_object = self.create_misp_object(related_file)
                related_file_object.add_reference(file_object.uuid, misp_name)
                self.misp_event.add_object(**related_file_object)

        self.misp_event.add_object(**file_object)
        return file_object.uuid

    def parse_ip(self, ip: str) -> str:
        ip_report = self.client.get_object(f"/ip_addresses/{ip}")

        # IP
        ip_object = self.create_misp_object(ip_report)

        # ASN
        asn_object = MISPObject("asn")
        asn_object.add_attribute("asn", type="AS", value=ip_report.asn)
        asn_object.add_attribute("subnet-announced", type="ip-src", value=ip_report.network)
        asn_object.add_attribute("country", type="text", value=ip_report.country)
        self.misp_event.add_object(**asn_object)

        # RESOLUTIONS
        resolutions_iterator = self.client.iterator(f"/ip_addresses/{ip_report.id}/resolutions", limit=self.limit)
        for resolution in resolutions_iterator:
            ip_object.add_attribute("domain", type="domain", value=resolution.host_name)

        self.misp_event.add_object(**ip_object)
        return ip_object.uuid

    def parse_url(self, url: str) -> str:
        url_id = vt.url_id(url)
        url_report = self.client.get_object(f"/urls/{url_id}")
        url_object = self.create_misp_object(url_report)
        self.misp_event.add_object(**url_object)
        return url_object.uuid


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format.
    If no proxy settings are set, return None."""
    proxies = None
    host = config.get("proxy_host")
    port = config.get("proxy_port")
    username = config.get("proxy_username")
    password = config.get("proxy_password")

    if host:
        if not port:
            misperrors["error"] = "The virustotal_proxy_host config is set, please also set the virustotal_proxy_port."
            raise KeyError
        parsed = urlparse(host)
        if "http" in parsed.scheme:
            scheme = "http"
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f"{netloc}:{port}"

        if username:
            if not password:
                misperrors["error"] = (
                    "The virustotal_proxy_username config is set, please also set the virustotal_proxy_password."
                )
                raise KeyError
            auth = f"{username}:{password}"
            host = auth + "@" + host

        proxies = {"http": f"{scheme}://{host}", "https": f"{scheme}://{host}"}
    return proxies


def parse_error(status_code: int) -> str:
    status_mapping = {
        204: "VirusTotal request rate limit exceeded.",
        400: "Incorrect request, please check the arguments.",
        403: "You don't have enough privileges to make the request.",
    }
    if status_code in status_mapping:
        return status_mapping[status_code]
    return "VirusTotal may not be accessible."


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "A VirusTotal api key is required for this module."
        return misperrors
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    event_limit = request["config"].get("event_limit")
    attribute = request["attribute"]
    proxy_settings = get_proxy_settings(request.get("config"))

    try:
        client = vt.Client(
            request["config"]["apikey"],
            headers={
                "x-tool": "MISPModuleVirusTotalPublicExpansion",
            },
            proxy=proxy_settings["http"] if proxy_settings else None,
        )
        parser = VirusTotalParser(client, int(event_limit) if event_limit else None)
        parser.query_api(attribute)
    except vt.APIError as ex:
        misperrors["error"] = ex.message
        return misperrors

    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
