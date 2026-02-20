import datetime
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from pymisp import MISPEvent, MISPObject

# Logging configuration
log = logging.getLogger("validin")
log.setLevel(logging.INFO)
stream = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
stream.setFormatter(formatter)
log.addHandler(stream)

# MISP Module Interface
misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "hostname", "ip-src", "ip-dst"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.2",
    "author": "Validin",
    "description": "Validin internet dataset expansion. Returns dns-records, web crawls, registration (WHOIS) records, and certificates from Validin's historic internet intelligence dataset.",
    "module-type": ["expansion", "hover"],
    "name": "Validin DNS History",
    "logo": "validin.png",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Queries Validin's datasets for: DNS history, subdomains, host responses, certificates and registration "
        "records (enterprise users only) to enrich domains and IPs in MISP. "
        "The configured lookback is 14 days for DNS, 21 days for web crawls, and "
        "30 days for registration history. To set this up correctly, you need to configure: a Validin api key, "
        "a Validin endpoint (e.g. app.validin.com), and a result_limit, which defaults to 100."
    ),
    "input": "domain, hostname, or IP address.",
    "output": "MISP dns-record objects plus optional subdomain attributes.",
}
moduleconfig = ["endpoint", "api_key", "result_limit"]


TYPE_MAPPING = {"ip4": "ip-dst", "ip6": "ip-dst", "dom": "domain", "string": "text"}
DNS_RELATION_MAPPING = {
    "A": "a-record",
    "AAAA": "aaaa-record",
    "NS": "ns-record",
    "NS_FOR": "ns-record",
    "WAYWARD_NS": "ns-record",
}
EXTRA_RELATION_MAPPING = {
    "SOA_MNAME": "soa-record",
    "SOA_MNAME_FOR": "soa-record",
    "SOA_RNAME": "soa-record",
    "SOA_RNAME_FOR": "soa-record",
    "WAYWARD_SOA_MNAME": "soa-record",
    "WAYWARD_SOA_RNAME": "soa-record",
    "MX": "mx-record",
    "MX_FOR": "mx-record",
    "WAYWARD_MX": "mx-record",
    "TXT": "txt-record",
    "WAYWARD_TXT": "txt-record",
    "CNAME": "cname-record",
    "CNAME_FOR": "cname-record",
    "HTTPS": "text",
    "HTTPS_FOR": "text",
    "SRV": "text",
    "SRV_TARGET_FOR": "text",
    "CAA": "text",
    "CAA_ISSUER_FOR": "text",
    "CAA_ISSUERWILD_FOR": "text",
    "WAYWARD_HTTPS": "text",
}
QUERY_RELATION_MAP = {
    "domain": ("queried-domain", "domain"),
    "hostname": ("queried-domain", "domain"),
    "ip-src": ("queried-ip", "ip-src"),
    "ip-dst": ("queried-ip", "ip-dst"),
}


class ValidinDNSClient:
    """Consolidated Validin API client for MISP expansion."""

    def __init__(self, endpoint: str, api_key: str, result_limit: int = 100, timeout: int = 30) -> None:
        if not endpoint:
            raise ValueError("Validin endpoint is missing.")
        if not api_key:
            raise ValueError("Validin API key is missing.")

        endpoint = endpoint.rstrip("/")
        endpoint = endpoint if endpoint.startswith('https://') else f"https://{endpoint}"
        self.base_endpoint = endpoint
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Validin-MISP/1.1",
            "Accept": "application/json",
            "Authorization": f"BEARER {api_key}"
        })
        self.result_limit = result_limit
        self.enterprise_mode = not endpoint.startswith('https://app.validin.com')

    def _query(self, path: str, query: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_endpoint}{path.format(query=quote(query, safe=''))}"
        params = params or {}
        params["limit"] = self.result_limit
        response = self.session.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def get_dns_history(self, attribute_type: str, query: str) -> Dict[str, Any]:
        path = "/api/axon/ip/dns/history/{query}" if "ip-" in attribute_type else "/api/axon/domain/dns/history/{query}"
        return self._query(path, query, params={"lookback": 14})

    def get_ptr_history(self, attribute_type: str, query: str) -> Dict[str, Any]:
        path = "/api/axon/ip/dns/hostname/{query}" if "ip-" in attribute_type else "/api/axon/domain/dns/hostname/{query}"
        return self._query(path, query, params={"lookback": 14})

    def get_extra_records(self, attribute_type: str, query: str) -> Dict[str, Any]:
        path = "/api/axon/ip/dns/extra/{query}" if "ip-" in attribute_type else "/api/axon/domain/dns/extra/{query}"
        return self._query(path, query, params={"lookback": 14})

    def get_subdomains(self, query: str) -> Dict[str, Any]:
        return self._query("/api/axon/domain/subdomains/{query}", query)

    def get_domain_certificates(self, query: str) -> Dict[str, Any]:
        return self._query("/api/axon/domain/certificates/{query}", query)

    def get_crawl_history(self, attribute_type: str, query: str) -> Dict[str, Any]:
        path = "/api/axon/ip/crawl/history/{query}" if attribute_type.startswith("ip-") else "/api/axon/domain/crawl/history/{query}"
        return self._query(path, query, params={"lookback": 21})

    def get_quick_reputation(self, attribute_type: str, query: str) -> Dict[str, Any]:
        """Queries the quick reputation endpoint."""
        path = "/api/axon/ip/reputation/quick/{query}" if "ip-" in attribute_type else "/api/axon/domain/reputation/quick/{query}"
        return self._query(path, query)

    def get_registration_history(self, query: str) -> Dict[str, Any]:
        return self._query("/api/axon/domain/registration/history/{query}", query, params={"lookback": 30})


def _add_time_attributes(dns_obj: MISPObject, record: Dict[str, Any]) -> None:
    for key, attr_name in (("first_seen", "first-seen"), ("last_seen", "last-seen")):
        timestamp = record.get(key)
        if not timestamp:
            continue
        dns_obj.add_attribute(attr_name, value=datetime.datetime.fromtimestamp(timestamp).isoformat(), type="datetime")


def _add_query_attribute(dns_obj: MISPObject, attribute: Dict[str, Any]) -> None:
    relation, attr_type = QUERY_RELATION_MAP.get(attribute["type"], ("queried-value", "text"))
    dns_obj.add_attribute(relation, value=attribute["value"], type=attr_type)


def _add_values(misp_object: MISPObject, relation: str, values: Optional[List[Any]], attr_type: str = "text") -> None:
    if not values:
        return
    for value in values:
        if value in (None, ""):
            continue
        misp_object.add_attribute(relation, value=value, type=attr_type)


def _add_role_attributes(whois_obj: MISPObject, role_name: str, role_data: Dict[str, Any]) -> None:
    role_label = role_name.lower()
    for field, values in role_data.items():
        if not isinstance(values, list):
            values = [values]
        attr_name = f"{role_label}-{field}".lower().replace("_", "-")
        field_lower = field.lower()
        attr_type = "text"
        if "email" in field_lower:
            attr_type = "email"
        elif "phone" in field_lower or "tel" in field_lower:
            attr_type = "phone-number"
        for value in values:
            if value in (None, ""):
                continue
            whois_obj.add_attribute(attr_name, value=value, type=attr_type)


def process_dns_enrichment(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = client.get_dns_history(attribute["type"], query)
    records_dict = payload.get("records", {})
    misp_event = MISPEvent()

    for record_type, record_list in records_dict.items():
        relation = DNS_RELATION_MAPPING.get(record_type)
        if not relation: continue

        for record in record_list:
            val = record.get("value")
            if not val: continue

            dns_obj = MISPObject("dns-record")
            dns_obj.add_attribute(relation, value=val, type=TYPE_MAPPING.get(record.get("value_type"), "text"))
            _add_query_attribute(dns_obj, attribute)
            dns_obj.add_attribute("type", value=record_type, type="text")

            _add_time_attributes(dns_obj, record)
            dns_obj.add_reference(attribute["uuid"], "related-to")
            misp_event.add_object(dns_obj)

    return json.loads(misp_event.to_json()).get("Object", [])


def process_ptr_enrichment(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = client.get_ptr_history(attribute["type"], query)
    records_dict = payload.get("records", {})
    misp_event = MISPEvent()

    for record_type, record_list in records_dict.items():
        for record in record_list:
            val = record.get("value")
            if not val: continue

            dns_obj = MISPObject("dns-record")
            dns_obj.add_attribute("ptr-record", value=val, type="domain")
            _add_query_attribute(dns_obj, attribute)
            dns_obj.add_attribute("type", value=record_type, type="text")
            _add_time_attributes(dns_obj, record)

            dns_obj.add_reference(attribute["uuid"], "related-to")
            misp_event.add_object(dns_obj)

    return json.loads(misp_event.to_json()).get("Object", [])

def process_extra_enrichment(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = client.get_extra_records(attribute["type"], query)
    records_dict = payload.get("records", {})
    misp_event = MISPEvent()

    for r_type, r_list in records_dict.items():
        relation = EXTRA_RELATION_MAPPING.get(r_type)
        if not relation: continue

        for record in r_list:
            val = record.get("value")
            if not val: continue

            dns_obj = MISPObject("dns-record")
            misp_type = "domain" if record.get("value_type") == "dom" else "text"

            dns_obj.add_attribute(relation, value=val, type=misp_type)
            _add_query_attribute(dns_obj, attribute)
            dns_obj.add_attribute("type", value=r_type, type="text")

            _add_time_attributes(dns_obj, record)
            dns_obj.add_reference(attribute["uuid"], "related-to")
            misp_event.add_object(dns_obj)

    return json.loads(misp_event.to_json()).get("Object", [])

def process_subdomain_enrichment(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    if attribute["type"].startswith("ip-"):
        return []

    payload = client.get_subdomains(query)
    subdomains = payload.get("records", {}).get("subdomains", [])

    # Return a raw list of attribute dicts
    return [{
        "type": "domain",
        "value": s["value"],
        "comment": f"Subdomain of {query}"
    } for s in subdomains if s.get("value")]


def process_registration_history(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:

    if not client.enterprise_mode:
        return []

    if attribute["type"] not in ("domain", "hostname"):
        return []

    payload = client.get_registration_history(query)
    registrations = payload.get("records", {}).get("registration", [])
    if not registrations:
        return []

    misp_event = MISPEvent()
    for record in registrations:
        whois_obj = MISPObject("whois")
        domain_value = record.get("domain") or record.get("key")
        if domain_value:
            whois_obj.add_attribute("domain", type="domain", value=domain_value)

        if record.get("date"):
            whois_obj.add_attribute("observation-date", type="datetime", value=record["date"])
        if "found" in record:
            whois_obj.add_attribute("found", type="boolean", value=record["found"])

        _add_values(whois_obj, "status", record.get("status"), "text")
        _add_values(whois_obj, "registrar", record.get("registrar"), "whois-registrar")
        _add_values(whois_obj, "registration-date", record.get("registered"), "datetime")
        _add_values(whois_obj, "expiration-date", record.get("expires"), "datetime")
        _add_values(whois_obj, "last-changed", record.get("changed"), "datetime")
        _add_values(whois_obj, "nameserver", record.get("nameservers"), "domain")
        _add_values(whois_obj, "related", record.get("related"), "link")

        s_dns = record.get("sDNS")
        if isinstance(s_dns, list):
            _add_values(whois_obj, "signed-dns", s_dns, "text")
        elif s_dns is not None:
            whois_obj.add_attribute("signed-dns", type="text", value=str(s_dns))

        if record.get("source"):
            whois_obj.add_attribute("source", type="link", value=record["source"])

        roles = record.get("roles") or {}
        for role_name, role_data in roles.items():
            if isinstance(role_data, dict):
                _add_role_attributes(whois_obj, role_name, role_data)

        whois_obj.add_reference(attribute["uuid"], "related-to")
        if whois_obj.attributes:
            misp_event.add_object(whois_obj)

    return json.loads(misp_event.to_json()).get("Object", [])


def process_certificate_history(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    if attribute["type"] not in ("domain", "hostname"):
        return []

    payload = client.get_domain_certificates(query)
    certificates = payload.get("records", {}).get("ctstream", [])
    if not certificates:
        return []

    def parse_not_before(entry: Dict[str, Any]) -> datetime.datetime:
        value = entry.get("value", {}).get("not_before")
        try:
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return datetime.datetime.min

    certificates.sort(key=parse_not_before, reverse=True)
    latest = certificates[0]
    cert_value = latest.get("value") or {}

    x509 = MISPObject("x509")
    if cert_value.get("common_name"):
        x509.add_attribute("subject", type="text", value=cert_value["common_name"])
    if cert_value.get("cert_issuer"):
        x509.add_attribute("issuer", type="text", value=cert_value["cert_issuer"])
    if cert_value.get("not_before"):
        x509.add_attribute("validity-not-before", type="datetime", value=cert_value["not_before"])
    if cert_value.get("not_after"):
        x509.add_attribute("validity-not-after", type="datetime", value=cert_value["not_after"])

    details = cert_value.get("details") or {}
    if details.get("fingerprint"):
        x509.add_attribute("x509-fingerprint-sha1", type="x509-fingerprint-sha1", value=details["fingerprint"])
    if details.get("fingerprint_sha256"):
        x509.add_attribute("x509-fingerprint-sha256", type="x509-fingerprint-sha256", value=details["fingerprint_sha256"])
    for domain_value in details.get("domains", []):
        if domain_value:
            x509.add_attribute("san", type="domain", value=domain_value)

    for link in cert_value.get("links", []):
        x509.add_attribute("source", type="link", value=link)

    timestamp = cert_value.get("timestamp")
    if timestamp:
        x509.add_attribute("observation-date", type="datetime", value=timestamp)

    x509.add_reference(attribute["uuid"], "related-to")
    misp_event = MISPEvent()
    misp_event.add_object(x509)
    return json.loads(misp_event.to_json()).get("Object", [])


def process_crawl_history(client: ValidinDNSClient, query: str, attribute: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = client.get_crawl_history(attribute["type"], query)
    crawls = payload.get("records", {}).get("crawlr", [])
    if not crawls:
        return []

    def parse_time(entry: Dict[str, Any]) -> datetime.datetime:
        try:
            return datetime.datetime.fromisoformat(entry.get("value", {}).get("time", "").replace("Z", "+00:00"))
        except Exception:
            return datetime.datetime.min

    sorted_crawls = sorted(crawls, key=parse_time, reverse=True)
    seen_ports = set()
    selected_crawls = []
    for crawl in sorted_crawls:
        port = (crawl.get("value") or {}).get("port")
        if port in (None, ""):
            continue
        port = int(port)
        if port in seen_ports:
            continue
        seen_ports.add(port)
        selected_crawls.append(crawl)

    if not selected_crawls:
        return []

    misp_event = MISPEvent()
    for record in selected_crawls:
        crawl_data = record.get("value") or {}
        request_obj = MISPObject("http-request")
        response_obj = MISPObject("http-response")

        host = crawl_data.get("host") or crawl_data.get("location_domain")
        if host:
            request_obj.add_attribute("host", type="hostname", value=host)

        ip_value = crawl_data.get("ip")
        scheme = crawl_data.get("scheme")
        port = crawl_data.get("port")
        if not scheme:
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                port_int = None
            scheme = "https" if port_int == 443 else "http"

        try:
            port_int = int(port)
        except (TypeError, ValueError):
            port_int = None

        path = crawl_data.get("path") or "/"
        if not path.startswith("/"):
            path = f"/{path}"

        url_host = host or ip_value
        if url_host:
            url = f"{scheme}://{url_host}"
            if port_int and (
                (scheme == "http" and port_int != 80)
                or (scheme == "https" and port_int != 443)
                or scheme not in ("http", "https")
            ):
                url = f"{url}:{port_int}"
            url = f"{url}{path}"
            request_obj.add_attribute("url", type="url", value=url)

        request_obj.add_attribute("method", type="http-method", value="GET")
        if ip_value:
            request_obj.add_attribute("ip", type="ip-dst", value=ip_value)

        if port_int:
            request_obj.add_attribute("port", type="port", value=port_int)

        if crawl_data.get("title"):
            request_obj.add_attribute("title", type="text", value=crawl_data["title"])

        response_line = crawl_data.get("response_line") or crawl_data.get("start_line")
        if response_line:
            response_obj.add_attribute("status-line", type="text", value=response_line)
        if crawl_data.get("banner"):
            response_obj.add_attribute("raw", type="text", value=crawl_data["banner"])
        if crawl_data.get("length"):
            response_obj.add_attribute("size-in-bytes", type="size-in-bytes", value=crawl_data["length"])
        if crawl_data.get("time"):
            response_obj.add_attribute("retrieval-time", type="datetime", value=crawl_data["time"])

        banner_full = crawl_data.get("banner_full") or []
        for line in banner_full:
            if line:
                response_obj.add_attribute("header-line", type="text", value=line)

        header_hash = crawl_data.get("header_hash")
        if header_hash:
            response_obj.add_attribute("header-md5", type="md5", value=header_hash)
        banner_hash = crawl_data.get("banner_0_hash") or crawl_data.get("banner_hash")
        if banner_hash:
            response_obj.add_attribute("banner-md5", type="md5", value=banner_hash)

        body_hash = crawl_data.get("body_hash")
        if body_hash:
            response_obj.add_attribute("body-sha1", type="sha1", value=body_hash)

        if crawl_data.get("title"):
            response_obj.add_attribute("title", type="text", value=crawl_data["title"])
        if crawl_data.get("location"):
            response_obj.add_attribute("redirect-to", type="url", value=crawl_data["location"])

        cert_sha256 = crawl_data.get("cert_fingerprint_sha256")
        if cert_sha256:
            response_obj.add_attribute("x509-fingerprint-sha256", type="x509-fingerprint-sha256", value=cert_sha256)

        cert = crawl_data.get("cert") or {}
        cert_details = crawl_data.get("cert_details") or {}
        if cert or cert_details:
            cert_obj = MISPObject("x509")
            issuer = cert.get("cert_issuer") or cert.get("issuer")
            if isinstance(issuer, dict):
                issuer_str = ", ".join(f"{k}={v}" for k, v in issuer.items() if v)
            else:
                issuer_str = issuer
            if issuer_str:
                cert_obj.add_attribute("issuer", type="text", value=issuer_str)
            for field, attr in (("not_before", "validity-not-before"), ("not_after", "validity-not-after")):
                if cert.get(field):
                    cert_obj.add_attribute(attr, type="datetime", value=cert[field])

            chain_fps = cert.get("chain_fingerprints") or []
            for fp in chain_fps:
                cert_obj.add_attribute("x509-fingerprint-sha1", type="x509-fingerprint-sha1", value=fp)

            for serial in crawl_data.get("cert_chain_serials") or []:
                cert_obj.add_attribute("serial-number", type="text", value=serial)

            details_fp = cert_details.get("fingerprint")
            if details_fp:
                cert_obj.add_attribute("x509-fingerprint-sha1", type="x509-fingerprint-sha1", value=details_fp)
            details_fp_sha256 = cert_details.get("fingerprint_sha256")
            if details_fp_sha256:
                cert_obj.add_attribute("x509-fingerprint-sha256", type="x509-fingerprint-sha256", value=details_fp_sha256)

            jarm = cert_details.get("jarm")
            if jarm:
                cert_obj.add_attribute("jarm-fingerprint", type="jarm-fingerprint", value=jarm)

            for domain_value in cert_details.get("domains") or []:
                if domain_value:
                    cert_obj.add_attribute("san", type="domain", value=domain_value)

            cert_obj.add_reference(attribute["uuid"], "related-to")
            misp_event.add_object(cert_obj)
            response_obj.add_reference(cert_obj.uuid, "uses")

        ext_links = crawl_data.get("ext_links") or {}
        ext_domains = set()
        for values in ext_links.values():
            if isinstance(values, list):
                for dom in values:
                    if dom:
                        ext_domains.add(dom)
        for dom in sorted(ext_domains):
            response_obj.add_attribute("external-domain", type="domain", value=dom)

        request_obj.add_reference(attribute["uuid"], "related-to")
        response_obj.add_reference(attribute["uuid"], "related-to")
        response_obj.add_reference(request_obj.uuid, "responds-to")

        misp_event.add_object(request_obj)
        misp_event.add_object(response_obj)

    return json.loads(misp_event.to_json()).get("Object", [])


def handler(q: Any = False) -> Any:
    if q is False: return False

    request = json.loads(q)
    config = request.get("config", {})
    attribute = request.get("attribute")

    if not attribute or not attribute.get("value"):
        return {"error": "Missing input attribute."}

    query_val = attribute["value"]

    raw_limit = config.get("result_limit")
    if raw_limit in (None, ""):
        result_limit = 100
    else:
        try:
            result_limit = int(raw_limit)
        except (TypeError, ValueError):
            return {"error": "result_limit must be an integer value."}
        if result_limit <= 0:
            return {"error": "result_limit must be a positive integer."}

    endpoint = config.get("endpoint", "app.validin.com")
    api_key = config.get("api_key", "")
    if not api_key:
        return {"error": "Validin API key is missing."}

    client = ValidinDNSClient(
        endpoint,
        api_key,
        result_limit=result_limit,
    )

    try:
        # These functions return Lists of OBJECTS
        obj_list = (
            process_dns_enrichment(client, query_val, attribute) +
            process_ptr_enrichment(client, query_val, attribute) +
            process_extra_enrichment(client, query_val, attribute) +
            process_registration_history(client, query_val, attribute) +
            process_certificate_history(client, query_val, attribute) +
            process_crawl_history(client, query_val, attribute)
        )

        # This function now returns a List of ATTRIBUTES
        attr_list = process_subdomain_enrichment(client, query_val, attribute)

        # Deduplicate Objects (as before) TODO: might not need this
        unique_objects = []
        seen_objs = set()
        for obj in obj_list:
            sig = json.dumps(obj.get("Attribute", []), sort_keys=True)
            if sig not in seen_objs:
                unique_objects.append(obj)
                seen_objs.add(sig)

        # Return both keys
        return {
            "results": {
                "Object": unique_objects,
                "Attribute": attr_list
            }
        }
    except Exception as e:
        return {"error": str(e)}

def hover(q: Any = False) -> Any:
    if q is False:
        return False

    request = json.loads(q)
    config = request.get("config", {})
    attribute = request.get("attribute")

    if not attribute or not attribute.get("value"):
        return {"error": "Missing input."}

    # Ensure endpoint starts with https://
    client = ValidinDNSClient(config.get("endpoint", ""), config.get("api_key", ""))
    query_val = attribute["value"]

    try:
        data = client.get_quick_reputation(attribute["type"], query_val)

        # Build a scannable summary string
        # Adjust these keys based on the actual JSON structure of Validin's quick response
        score = data.get("score", "N/A")
        tags = ", ".join(data.get("tags", [])) if data.get("tags") else "No tags"
        first_seen = data.get("first_seen", "Unknown")

        summary = [
            f"Validin Reputation Score: {score}",
            f"Tags: {tags}",
            f"First Seen: {first_seen}"
        ]

        # MISP hover requires this exact 'summary' key
        return {"summary": "\n".join(summary)}

    except Exception as e:
        return {"error": f"Hover failed: {str(e)}"}

def introspection() -> Dict[str, Any]:
    return mispattributes


def version() -> Dict[str, Any]:
    moduleinfo["config"] = moduleconfig
    return moduleinfo
