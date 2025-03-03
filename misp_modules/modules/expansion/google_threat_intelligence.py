#!/usr/local/bin/python
# Copyright © 2024 The Google Threat Intelligence authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Google Threat Intelligence MISP expansion module."""

from urllib import parse

import pymisp
import vt

mispattributes = {
    "input": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst",
        "md5",
        "sha1",
        "sha256",
        "url",
    ],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "2",
    "author": "Google Threat Intelligence team",
    "description": "An expansion module to have the observable's threat score assessed by Google Threat Intelligence.",
    "module-type": ["expansion"],
    "name": "Google Threat Intelligence Lookup",
    "config": [
        "apikey",
        "event_limit",
        "proxy_host",
        "proxy_port",
        "proxy_username",
        "proxy_password",
    ],
    "logo": "google_threat_intelligence.png",
    "requirements": ["An access to the Google Threat Intelligence API (apikey), with a high request rate limit."],
    "features": (
        "GTI assessment for the given observable, this include information about level of severity, a clear verdict"
        " (malicious, suspicious, undetected and benign) and additional information provided by the Mandiant expertise"
        " combined with the VirusTotal database.\n\n[Output example"
        " screeshot](https://github.com/MISP/MISP/assets/4747608/e275db2f-bb1e-4413-8cc0-ec3cb05e0414)"
    ),
    "references": [
        "https://www.virustotal.com/",
        "https://gtidocs.virustotal.com/reference",
    ],
    "input": "A domain, hash (md5, sha1, sha256 or sha512), hostname or IP address attribute.",
    "output": (
        "Text fields containing the threat score, the severity, the verdict and the threat label of the observable"
        " inspected."
    ),
}

DEFAULT_RESULTS_LIMIT = 10


class GoogleThreatIntelligenceParser:
    """Main parser class to create the MISP event."""

    def __init__(self, client: vt.Client, limit: int) -> None:
        self.client = client
        self.limit = limit or DEFAULT_RESULTS_LIMIT
        self.misp_event = pymisp.MISPEvent()
        self.attribute = pymisp.MISPAttribute()
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
            "ip-src|port": self.parse_ip_port,
            "ip-dst|port": self.parse_ip_port,
        }
        self.proxies = None

    @staticmethod
    def get_total_analysis(analysis: dict, known_distributors: dict = None) -> int:
        """Get total"""
        if not analysis:
            return 0
        count = sum([analysis["undetected"], analysis["suspicious"], analysis["harmless"]])
        return count if known_distributors else count + analysis["malicious"]

    def query_api(self, attribute: dict) -> None:
        """Get data from the API and parse it."""
        self.attribute.from_dict(**attribute)
        self.input_types_mapping[self.attribute.type](self.attribute.value)

    def get_results(self) -> dict:
        """Serialize the MISP event."""
        event = self.misp_event.to_dict()
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def add_gti_report(self, report: vt.Object) -> str:
        analysis = report.get("last_analysis_stats")
        total = self.get_total_analysis(analysis, report.get("known_distributors"))
        if report.type == "ip_address":
            rtype = "ip-address"
        else:
            rtype = report.type
        permalink = f"https://www.virustotal.com/gui/{rtype}/{report.id}"

        gti_object = pymisp.MISPObject("google-threat-intelligence-report")
        gti_object.add_attribute("permalink", type="link", value=permalink)
        ratio = f"{analysis['malicious']}/{total}" if analysis else "-/-"
        gti_object.add_attribute("detection-ratio", type="text", value=ratio, disable_correlation=True)
        report_dict = report.to_dict()
        gti_object.add_attribute(
            "threat-score",
            type="text",
            value=get_key(report_dict, "attributes.gti_assessment.threat_score.value"),
        )
        gti_object.add_attribute(
            "verdict",
            type="text",
            value=get_key(report_dict, "attributes.gti_assessment.verdict.value").replace("VERDICT_", ""),
        )
        gti_object.add_attribute(
            "severity",
            type="text",
            value=get_key(report_dict, "attributes.gti_assessment.severity.value").replace("SEVERITY_", ""),
        )
        self.misp_event.add_object(**gti_object)
        return gti_object.uuid

    def create_misp_object(self, report: vt.Object) -> pymisp.MISPObject:
        misp_object = None
        gti_uuid = self.add_gti_report(report)

        if report.type == "file":
            misp_object = pymisp.MISPObject("file")
            for hash_type in (
                "md5",
                "sha1",
                "sha256",
                "tlsh",
                "vhash",
                "ssdeep",
                "imphash",
            ):
                misp_object.add_attribute(hash_type, **{"type": hash_type, "value": report.get(hash_type)})
        elif report.type == "domain":
            misp_object = pymisp.MISPObject("domain-ip")
            misp_object.add_attribute("domain", type="domain", value=report.id)
        elif report.type == "ip_address":
            misp_object = pymisp.MISPObject("domain-ip")
            misp_object.add_attribute("ip", type="ip-dst", value=report.id)
        elif report.type == "url":
            misp_object = pymisp.MISPObject("url")
            misp_object.add_attribute("url", type="url", value=report.id)
        misp_object.add_reference(gti_uuid, "analyzed-with")
        return misp_object

    def parse_domain(self, domain: str) -> str:
        domain_report = self.client.get_object(f"/domains/{domain}")

        # DOMAIN
        domain_object = self.create_misp_object(domain_report)

        # WHOIS
        if domain_report.whois:
            whois_object = pymisp.MISPObject("whois")
            whois_object.add_attribute("text", type="text", value=domain_report.whois)
            self.misp_event.add_object(**whois_object)

        # SIBLINGS AND SUBDOMAINS
        for relationship_name, misp_name in [
            ("siblings", "sibling-of"),
            ("subdomains", "subdomain"),
        ]:
            rel_iterator = self.client.iterator(f"/domains/{domain_report.id}/{relationship_name}", limit=self.limit)
            for item in rel_iterator:
                attr = pymisp.MISPAttribute()
                attr.from_dict(**dict(type="domain", value=item.id))
                self.misp_event.add_attribute(**attr)
                domain_object.add_reference(attr.uuid, misp_name)

        # RESOLUTIONS
        resolutions_iterator = self.client.iterator(f"/domains/{domain_report.id}/resolutions", limit=self.limit)
        for resolution in resolutions_iterator:
            domain_object.add_attribute("ip", type="ip-dst", value=resolution.ip_address)

        # COMMUNICATING, DOWNLOADED AND REFERRER FILES
        for relationship_name, misp_name in [
            ("communicating_files", "communicates-with"),
            ("downloaded_files", "downloaded-from"),
            ("referrer_files", "referring"),
        ]:
            files_iterator = self.client.iterator(f"/domains/{domain_report.id}/{relationship_name}", limit=self.limit)
            for file in files_iterator:
                file_object = self.create_misp_object(file)
                file_object.add_reference(domain_object.uuid, misp_name)
                self.misp_event.add_object(**file_object)

        # URLS
        urls_iterator = self.client.iterator(f"/domains/{domain_report.id}/urls", limit=self.limit)
        for url in urls_iterator:
            url_object = self.create_misp_object(url)
            url_object.add_reference(domain_object.uuid, "hosted-in")
            self.misp_event.add_object(**url_object)

        self.misp_event.add_object(**domain_object)
        return domain_object.uuid

    def parse_hash(self, file_hash: str) -> str:
        file_report = self.client.get_object(f"/files/{file_hash}")
        file_object = self.create_misp_object(file_report)

        # ITW URLS
        urls_iterator = self.client.iterator(f"/files/{file_report.id}/itw_urls", limit=self.limit)
        for url in urls_iterator:
            url_object = self.create_misp_object(url)
            url_object.add_reference(file_object.uuid, "downloaded")
            self.misp_event.add_object(**url_object)

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

    def parse_ip_port(self, ipport: str) -> str:
        ip = ipport.split("|")[0]
        self.parse_ip(ip)

    def parse_ip(self, ip: str) -> str:
        ip_report = self.client.get_object(f"/ip_addresses/{ip}")

        # IP
        ip_object = self.create_misp_object(ip_report)

        # ASN
        asn_object = pymisp.MISPObject("asn")
        asn_object.add_attribute("asn", type="AS", value=ip_report.asn)
        asn_object.add_attribute("subnet-announced", type="ip-src", value=ip_report.network)
        asn_object.add_attribute("country", type="text", value=ip_report.country)
        self.misp_event.add_object(**asn_object)

        # RESOLUTIONS
        resolutions_iterator = self.client.iterator(f"/ip_addresses/{ip_report.id}/resolutions", limit=self.limit)
        for resolution in resolutions_iterator:
            ip_object.add_attribute("domain", type="domain", value=resolution.host_name)

        # URLS
        urls_iterator = self.client.iterator(f"/ip_addresses/{ip_report.id}/urls", limit=self.limit)
        for url in urls_iterator:
            url_object = self.create_misp_object(url)
            url_object.add_reference(ip_object.uuid, "hosted-in")
            self.misp_event.add_object(**url_object)

        self.misp_event.add_object(**ip_object)
        return ip_object.uuid

    def parse_url(self, url: str) -> str:
        url_id = vt.url_id(url)
        url_report = self.client.get_object(f"/urls/{url_id}")
        url_object = self.create_misp_object(url_report)

        # COMMUNICATING, DOWNLOADED AND REFERRER FILES
        for relationship_name, misp_name in [
            ("communicating_files", "communicates-with"),
            ("downloaded_files", "downloaded-from"),
            ("referrer_files", "referring"),
        ]:
            files_iterator = self.client.iterator(f"/urls/{url_report.id}/{relationship_name}", limit=self.limit)
            for file in files_iterator:
                file_object = self.create_misp_object(file)
                file_object.add_reference(url_object.uuid, misp_name)
                self.misp_event.add_object(**file_object)

        self.misp_event.add_object(**url_object)
        return url_object.uuid


def get_key(dictionary, key, default_value=""):
    """Get value from nested dictionaries."""
    dictionary = dictionary or {}
    keys = key.split(".")
    field_name = keys.pop()
    for k in keys:
        if k not in dictionary:
            return default_value
        dictionary = dictionary[k]
    return dictionary.get(field_name, default_value)


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format or None if not set up."""
    proxies = None
    host = config.get("proxy_host")
    port = config.get("proxy_port")
    username = config.get("proxy_username")
    password = config.get("proxy_password")

    if host:
        if not port:
            raise KeyError(
                "The google_threat_intelligence_proxy_host config is set, please also set the virustotal_proxy_port."
            )
        parsed = parse.urlparse(host)
        if "http" in parsed.scheme:
            scheme = "http"
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f"{netloc}:{port}"

        if username:
            if not password:
                raise KeyError(
                    "The google_threat_intelligence_"
                    " proxy_host config is set, please also"
                    " set the virustotal_proxy_password."
                )
            auth = f"{username}:{password}"
            host = auth + "@" + host

        proxies = {"http": f"{scheme}://{host}", "https": f"{scheme}://{host}"}
    return proxies


def dict_handler(request: dict):
    """MISP entry point fo the module."""
    if not request.get("config") or not request["config"].get("apikey"):
        return {"error": "A Google Threat Intelligence api key is required for this module."}

    if not request.get("attribute"):
        return {
            "error": (
                'This module requires an "attribute" field as input,'
                " which should contain at least a type, a value and an"
                " uuid."
            )
        }

    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    event_limit = request["config"].get("event_limit")
    attribute = request["attribute"]

    try:
        proxy_settings = get_proxy_settings(request.get("config"))
        client = vt.Client(
            request["config"]["apikey"],
            headers={
                "x-tool": "MISPModuleGTIExpansion",
            },
            proxy=proxy_settings["http"] if proxy_settings else None,
        )
        parser = GoogleThreatIntelligenceParser(client, int(event_limit) if event_limit else None)
        parser.query_api(attribute)
    except vt.APIError as ex:
        return {"error": ex.message}
    except KeyError as ex:
        return {"error": str(ex)}

    return parser.get_results()


def introspection():
    """Returns the module input attributes required."""
    return mispattributes


def version():
    """Returns the module metadata."""
    return moduleinfo


if __name__ == "__main__":
    # Testing/debug calls.
    import os

    api_key = os.getenv("GTI_API_KEY")
    # File
    request_data = {
        "config": {"apikey": api_key},
        "attribute": {
            "type": "sha256",
            "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        },
    }
    response = dict_handler(request_data)
    report_obj = response["results"]["Object"][0]
    print(report_obj.to_dict())

    # URL
    request_data = {
        "config": {"apikey": api_key},
        "attribute": {"type": "url", "value": "http://47.21.48.182:60813/Mozi.a"},
    }
    response = dict_handler(request_data)
    report_obj = response["results"]["Object"][0]
    print(report_obj.to_dict())

    # Ip
    request_data = {
        "config": {"apikey": api_key},
        "attribute": {"type": "ip-src", "value": "180.72.148.38"},
    }
    response = dict_handler(request_data)
    report_obj = response["results"]["Object"][0]
    print(report_obj.to_dict())

    # Domain
    request_data = {
        "config": {"apikey": api_key},
        "attribute": {"type": "domain", "value": "qexyhuv.com"},
    }
    response = dict_handler(request_data)
    report_obj = response["results"]["Object"][0]
    print(report_obj.to_dict())
