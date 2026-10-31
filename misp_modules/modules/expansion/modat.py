"""MODAT Magnify enrichment using the documented v1 API (OpenAPI 1.65.2)."""

import base64
import ipaddress
import json
import logging
import math
import re
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import InvalidMISPObject, PyMISPError

LOGGER = logging.getLogger("misp-modules.modat")

BASE_URL = "https://api.magnify.modat.io"
DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "modat"
SERVICE_MAPPING = json.loads((DATA_PATH / "service_mapping.json").read_text())
FIELD_INPUTS = {
    "AS": ("asn.number",),
    "domain": ("fqdns",),
    "hostname": ("fqdns", "rdns"),
    "port": ("port",),
    "x509-fingerprint-sha1": ("tls.fingerprint_sha1",),
    "x509-fingerprint-sha256": ("tls.fingerprint_sha256",),
    "jarm-fingerprint": ("tls.jarm",),
    "hasshserver-md5": ("ssh.hassh",),
    "ssh-fingerprint": ("ssh.key_exchange.server_host_key.fingerprint_sha256",),
    "favicon-mmh3": ("http.files.mmh3",),
    "vulnerability": ("cves.id",),
    "sha1": ("banner_sha1", "http.body_sha1", "http.files.sha1"),
    "sha256": ("banner_sha256", "http.body_sha256", "http.files.sha256", "http.headers_sha256"),
    "email": ("tls.extensions.subject_alt_name.email", "tls.extensions.issuer_alt_name.email"),
    "target-org": ("asn.org", "tls.subject.organization", "tls.issuer.organization"),
}
for _type in ("email-src", "email-dst", "target-email"):
    FIELD_INPUTS[_type] = FIELD_INPUTS["email"]
mispattributes = {
    "input": sorted(
        set(FIELD_INPUTS)
        | {
            "ip-src",
            "ip-dst",
            "ip-src|port",
            "ip-dst|port",
            "domain|ip",
            "hostname|port",
            "url",
            "uri",
            "link",
            "filename|sha1",
            "filename|sha256",
            "text",
            "hex",
            "pattern-in-traffic",
        }
    ),
    "format": "misp_standard",
}
moduleconfig = ["apikey", "max_results", "page_size", "timeout", "include_dns", "reverse_dns"]
DEFAULT_CONFIG = {"max_results": 1, "page_size": 10, "timeout": 10, "include_dns": True, "reverse_dns": True}
moduleinfo = {
    "version": "1.0",
    "author": "MISP",
    "description": "Enrich internet infrastructure using MODAT Magnify host, service and DNS observations.",
    "module-type": ["expansion"],
    "name": "MODAT Magnify",
    "requirements": [
        "requests",
        "PyMISP",
        "MODAT Magnify API key",
        "Install the bundled modat-service and modat-dns-record object templates in MISP",
    ],
    "references": ["https://api.magnify.modat.io/docs", "https://magnify.modat.io/docs"],
    "features": "Typed service and DNS observations linked to existing MISP infrastructure objects.",
    "input": "IPs, domains, network composites, certificate/SSH fingerprints, web hashes and CVEs.",
    "output": "MISP objects and source JSON attachments; discovered attributes have to_ids disabled.",
}


class ModatError(ValueError):
    pass


class ModatPermissionError(ModatError):
    pass


@contextmanager
def _subscription_access(endpoint):
    try:
        yield
    except ModatPermissionError:
        LOGGER.warning("MODAT %s denied by subscription (HTTP 403); continuing other endpoints.", endpoint)


def _quote(value):
    # Keep untrusted values in one literal; forbid escapes whose DSL behavior is undocumented.
    if any(c in value for c in ('"', "\\")) or any(ord(c) < 32 for c in value):
        raise ModatError("Values containing quotes, backslashes or control characters are unsupported.")
    return f'"{value}"'


def _ip(value):
    return str(ipaddress.ip_address(value.replace("[.]", ".").replace("{.}", ".")))


def _domain(value):
    value = value.replace("[.]", ".").replace("{.}", ".").rstrip(".")
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", p) for p in value.split(".")
    ):
        raise ModatError("Invalid domain or hostname.")
    return value


def _port(value):
    if not str(value).isdigit() or not 1 <= int(value) <= 65535:
        raise ModatError("Port must be between 1 and 65535.")
    return str(int(value))


def _term(fields, value, operator="="):
    terms = [f"{field}{operator}{_quote(value)}" for field in fields]
    return terms[0] if len(terms) == 1 else f'({" OR ".join(terms)})'


def build_query(attribute):
    """Return (direct IP lookup, service query, DNS zone name)."""
    typ, value = attribute["type"], str(attribute["value"]).strip()
    if typ not in mispattributes["input"]:
        raise ModatError("Unsupported attribute type.")
    if not value:
        raise ModatError("Attribute value is empty.")
    if typ in ("ip-src", "ip-dst"):
        if "/" in value:
            network = str(ipaddress.ip_network(value, strict=False))
            return None, _term(("subnet",), network), None
        return _ip(value), None, None
    if typ in ("ip-src|port", "ip-dst|port", "hostname|port", "domain|ip"):
        parts = value.split("|")
        if len(parts) != 2:
            raise ModatError("Composite attributes require exactly two components.")
        left, right = parts
        if typ == "domain|ip":
            zone = _domain(left)
            return None, f'{_term(("fqdns",), zone)} AND {_term(("ip",), _ip(right))}', zone
        zone = _domain(left) if typ == "hostname|port" else None
        field = "fqdns" if zone else "ip"
        return None, f"{_term((field,), zone or _ip(left))} AND port={_port(right)}", zone
    if typ in ("url", "uri", "link"):
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ModatError("Provide an absolute HTTP(S) URL without credentials.")
        port = _port(parsed.port or (443 if parsed.scheme == "https" else 80))
        try:
            host, zone, field = _ip(parsed.hostname), None, "ip"
        except ValueError:
            host, zone, field = _domain(parsed.hostname), _domain(parsed.hostname), "fqdns"
        return None, f"{_term((field,), host)} AND port={port}", zone
    if typ.startswith("filename|"):
        parts = value.rsplit("|", 1)
        if len(parts) != 2 or not parts[0]:
            raise ModatError("Invalid filename/hash composite.")
        typ, value = typ.split("|")[1], parts[1]
    if typ in ("domain", "hostname"):
        value = _domain(value)
        return None, _term(FIELD_INPUTS[typ], value), value
    if typ == "AS":
        value = value.upper().removeprefix("AS")
        if not value.isdigit() or not 0 <= int(value) <= 4294967295:
            raise ModatError("Invalid autonomous system number.")
    if typ == "port":
        value = _port(value)
    hash_lengths = {
        "sha1": 40,
        "sha256": 64,
        "x509-fingerprint-sha1": 40,
        "x509-fingerprint-sha256": 64,
        "hasshserver-md5": 32,
    }
    if typ in hash_lengths:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{hash_lengths[typ]}}}", value):
            raise ModatError("Invalid fingerprint or hash.")
        value = value.lower()
    if typ == "ssh-fingerprint" and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ModatError("MODAT SSH fingerprints require a 64-character hexadecimal SHA256 digest.")
    if typ == "ssh-fingerprint":
        value = value.lower()
    if typ == "jarm-fingerprint" and not re.fullmatch(r"[0-9a-fA-F]{62}", value):
        raise ModatError("Invalid JARM fingerprint.")
    if typ == "favicon-mmh3":
        if not re.fullmatch(r"-?\d+", value) or not -(2**31) <= int(value) < 2**31:
            raise ModatError("Invalid signed 32-bit favicon MMH3 hash.")
    if typ == "vulnerability":
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
            raise ModatError("Only CVE vulnerability identifiers are supported.")
        value = value.upper()
    if typ == "text":
        return None, _quote(value), None
    if typ == "pattern-in-traffic":
        return None, _term(("banner",), value, "~"), None
    if typ == "hex":
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
            raise ModatError("Invalid banner hexadecimal bytes.")
        return None, _term(("banner_hex",), value.lower()), None
    query = _term(FIELD_INPUTS[typ], value)
    if len(query) > 2000:
        raise ModatError("Query exceeds the API's 2000-character limit.")
    return None, query, None


def _config_value(config, key, default):
    value = config.get(key)
    if isinstance(value, str):
        value = value.strip()
    return default if value is None or value == "" else value


def _integer(config, key, default, minimum, maximum):
    value = _config_value(config, key, default)
    if isinstance(value, bool) or not re.fullmatch(r"\d+", str(value)):
        raise ModatError(f"{key} must be an integer.")
    value = int(value)
    if not minimum <= value <= maximum:
        raise ModatError(f"{key} must be between {minimum} and {maximum}.")
    return value


def _boolean(config, key, default):
    value = _config_value(config, key, default)
    if isinstance(value, bool):
        return value
    if str(value).lower() in ("true", "1", "yes"):
        return True
    if str(value).lower() in ("false", "0", "no"):
        return False
    raise ModatError(f"{key} must be true or false.")


class ModatClient:
    def __init__(self, key, timeout):
        self.session = requests.Session()
        self.session.headers.update({"Authorization": key, "Accept": "application/json"})
        self.timeout = timeout
        self.permission_denied = False

    def request(self, path, payload=None):
        response = self.session.request(
            "GET" if payload is None else "POST",
            f"{BASE_URL}{path}",
            json=payload,
            timeout=self.timeout,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            retry = response.headers.get("Retry-After", "")
            suffix = f" Retry after {retry} seconds." if re.fullmatch(r"\d+(?:\.\d+)?", retry) else ""
            raise ModatError(f"MODAT rate limit exceeded.{suffix}")
        if response.status_code == 401:
            raise ModatError("MODAT authentication failed (HTTP 401).")
        if response.status_code == 403:
            self.permission_denied = True
            raise ModatPermissionError("MODAT subscription does not permit this endpoint (HTTP 403).")
        if response.status_code != 200:
            raise ModatError(f"MODAT returned HTTP {response.status_code}.")
        try:
            data = response.json()
        except ValueError as exc:
            raise ModatError("MODAT returned invalid JSON.") from exc
        if not isinstance(data, dict) or "errors" in data:
            raise ModatError("MODAT returned an invalid response or rejected the query.")
        return data

    def search(self, endpoint, query, limit, page_size):
        results = []
        for page in range(1, math.ceil(limit / page_size) + 1):
            try:
                data = self.request(endpoint, {"query": query, "page": page, "page_size": page_size})
            except ModatPermissionError:
                if not results:
                    raise
                LOGGER.warning("MODAT search pagination denied (HTTP 403); retaining earlier pages.")
                break
            if data is None:
                raise ModatError("MODAT search endpoint was not found.")
            rows = data.get("page")
            total_pages = data.get("total_pages")
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise ModatError("MODAT returned an invalid search page.")
            if not isinstance(total_pages, int) or total_pages < 0:
                raise ModatError("MODAT returned invalid pagination metadata.")
            results.extend(rows[: limit - len(results)])
            if len(results) >= limit or not rows or page >= total_pages:
                break
        return results


def _leaves(data, prefix=""):
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _leaves(value, f"{prefix}.{key}" if prefix else key)
    elif isinstance(data, list):
        for item in data:
            yield from _leaves(item, prefix)
    elif data is not None and data != "":
        yield prefix, data


class ModatParser:
    def __init__(self, attribute):
        self.event = MISPEvent()
        self.source = MISPAttribute()
        self.source.from_dict(**attribute)
        self.event.add_attribute(**self.source.to_dict())
        self.objects = {}
        self.host_attachments = {}
        self.zones = set()

    @staticmethod
    def add(obj, relation, value, **kwargs):
        if value is None or value == "":
            return
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item is None or item == "":
                continue
            if not any(a.object_relation == relation and str(a.value) == str(item) for a in obj.attributes):
                obj.add_attribute(relation, value=item, to_ids=False, **kwargs)

    @staticmethod
    def raw(obj, value):
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
        obj.add_attribute(
            "raw-json", value="modat-observation.json", data=base64.b64encode(payload).decode(), to_ids=False
        )

    def put(self, obj, parent=None, relationship="associated-to"):
        if not obj.attributes:
            return None
        required_one_of = obj._definition.get("requiredOneOf", [])
        if required_one_of and not any(a.object_relation in required_one_of for a in obj.attributes):
            return None
        try:
            obj._validate()
        except InvalidMISPObject:
            counts = Counter(a.object_relation for a in obj.attributes)
            attributes = obj._definition.get("attributes", {})
            repeated = sorted(
                rel for rel, count in counts.items() if count > 1 and not attributes.get(rel, {}).get("multiple")
            )
            missing = sorted(set(obj._definition.get("required", [])) - set(counts))
            details = []
            if repeated:
                details.append("single-valued relations repeated: " + ", ".join(repeated))
            if missing:
                details.append("required relations missing: " + ", ".join(missing))
            reason = "; ".join(details) or "template constraints not satisfied"
            message = f"Cannot validate MISP object '{obj.name}': {reason}."
            # Describe template constraints only, never attribute values or exception contents.
            LOGGER.warning("%s", message)
            raise ModatError(message) from None
        # Attribute content identifies shared objects; references do not participate in deduplication.
        signature = json.dumps(
            [(a.object_relation, str(a.value), a.to_dict().get("data")) for a in obj.attributes], sort_keys=True
        )
        key = (obj.name, signature)
        if key not in self.objects:
            # Keep PyMISP's fresh identity; the cache only deduplicates this response.
            self.objects[key] = obj
            self.event.add_object(obj)
        obj = self.objects[key]
        target = str(parent or self.source.uuid)
        if not any(str(r.referenced_uuid) == target and r.relationship_type == relationship for r in obj.references):
            obj.add_reference(target, relationship)
        return obj

    @staticmethod
    def custom(name):
        return MISPObject(name, strict=True, misp_objects_path_custom=DATA_PATH)

    def infrastructure(self, data, parent):
        asn = data.get("asn") or {}
        if asn.get("number") is not None:
            obj = MISPObject("asn", strict=True)
            for rel, val in (
                ("asn", f"AS{asn['number']}"),
                ("description", asn.get("org")),
                ("subnet-announced", asn.get("netblock")),
            ):
                self.add(obj, rel, val)
            self.put(obj, parent)
        geo = data.get("geo") or {}
        if geo:
            obj = MISPObject("geolocation", strict=True)
            for field, rel in (
                ("city_name", "city"),
                ("country_name", "country"),
                ("country_iso_code", "countrycode"),
                ("accuracy_radius", "accuracy-radius"),
            ):
                self.add(obj, rel, geo.get(field))
            coords = geo.get("location")
            if isinstance(coords, list) and len(coords) == 2:
                self.add(obj, "longitude", coords[0])
                self.add(obj, "latitude", coords[1])
            self.put(obj, parent)

    def vulnerabilities(self, values, parent):
        for cve in values or []:
            if not isinstance(cve, dict) or not cve.get("id"):
                continue
            obj = MISPObject("vulnerability", strict=True)
            self.add(obj, "id", cve["id"])
            self.add(obj, "cvss-score", cve.get("cvss"))
            if cve.get("is_kev") is not None:
                self.add(
                    obj,
                    "description",
                    f"MODAT reports is_kev={str(cve['is_kev']).lower()}; inferred exposure, not verified exploitation.",
                )
            self.put(obj, parent, "vulnerability-of")

    def host(self, data):
        if not isinstance(data, dict) or not data.get("ip"):
            raise ModatError("MODAT host/service response has no IP address.")
        ip = _ip(data["ip"])
        obj = MISPObject("ip-port", strict=True)
        self.add(obj, "ip", ip)
        self.add(obj, "domain", data.get("fqdns"))
        rdns = data.get("rdns") or []
        if not isinstance(rdns, list) or not all(isinstance(name, str) for name in rdns):
            raise ModatError("MODAT returned invalid reverse DNS names.")
        rdns = list(dict.fromkeys(name for name in rdns if name))
        # ip-port permits one PTR value; dns-record can preserve the complete answer set.
        if len(rdns) == 1:
            self.add(obj, "ptr-record", rdns[0])
        notes = []
        if data.get("is_anycast") is not None:
            notes.append(f"MODAT is_anycast={str(data['is_anycast']).lower()}")
        notes.extend(f"MODAT classification: {tag}" for tag in data.get("tags") or [])
        # The standard ip-port template permits one text attribute.
        self.add(obj, "text", "\n".join(notes))
        host = self.put(obj)
        if rdns:
            reverse_dns = MISPObject("dns-record", strict=True)
            self.add(reverse_dns, "queried-domain", ipaddress.ip_address(ip).reverse_pointer)
            self.add(reverse_dns, "ptr-record", rdns)
            self.put(reverse_dns, host.uuid)
        self.infrastructure(data, host.uuid)
        self.vulnerabilities(data.get("cves"), host.uuid)
        # Preserve extensions and all original nested data as evidence, without inventing attribute semantics.
        payload = base64.b64encode(json.dumps(data, sort_keys=True).encode()).decode()
        if payload not in self.host_attachments:
            attachment = self.event.add_attribute(
                "attachment",
                value="modat-host.json",
                data=payload,
                to_ids=False,
                comment=f"MODAT observation for {ip}",
            )
            self.host_attachments[payload] = attachment.uuid
        raw_uuid = self.host_attachments[payload]
        if not any(str(r.referenced_uuid) == str(raw_uuid) for r in host.references):
            host.add_reference(str(raw_uuid), "derived-from")
        services = data.get("services", [data["service"]] if "service" in data else [])
        if not isinstance(services, list):
            raise ModatError("MODAT returned an invalid services list.")
        for service in services:
            if not isinstance(service, dict):
                raise ModatError("MODAT returned an invalid service.")
            self.service(ip, service, host.uuid)

    def service(self, ip, data, parent):
        obj = self.custom("modat-service")
        self.add(obj, "ip", ip)
        for path, value in _leaves(data):
            if path in SERVICE_MAPPING:
                self.add(obj, SERVICE_MAPPING[path], value)
        # Search responses use a singular port; host details cluster equivalent observations into ports.
        self.add(obj, "ports", data.get("port"))
        self.raw(obj, data)
        service = self.put(obj, parent)
        ports = data.get("ports", [data["port"]] if "port" in data else [])
        for port in ports:
            endpoint = MISPObject("ip-port", strict=True)
            self.add(endpoint, "ip", ip)
            self.add(endpoint, "dst-port", port)
            self.add(endpoint, "protocol", data.get("transport"))
            self.add(endpoint, "first-seen", data.get("discovered_at"))
            self.add(endpoint, "last-seen", data.get("scanned_at"))
            self.put(endpoint, service.uuid)
        tls = data.get("tls") or {}
        if tls:
            cert = MISPObject("x509", strict=True)
            for field, relation in (
                ("fingerprint_sha1", "x509-fingerprint-sha1"),
                ("fingerprint_sha256", "x509-fingerprint-sha256"),
                ("serial_number", "serial-number"),
                ("valid_from", "validity-not-before"),
                ("expires_at", "validity-not-after"),
                ("is_self_signed", "is_self_signed"),
                ("raw", "text"),
            ):
                self.add(cert, relation, tls.get(field))
            dn_mapping = {
                "common_name": "common-name",
                "country": "country",
                "organization": "organization",
                "organizational_unit": "organizational-unit",
                "province": "state-or-province-name",
                "locality": "locality",
            }
            for side in ("issuer", "subject"):
                dn = tls.get(side) or {}
                for field, relation in dn_mapping.items():
                    values = list(dict.fromkeys(dn.get(field) or []))
                    # Specialized x509 DN relations are single-valued. Repeated RDNs
                    # are retained in the full DN below and the MODAT observation.
                    if len(values) == 1:
                        self.add(cert, f"{side}-{relation}", values[0])
                if dn:
                    # Render an X.509 distinguished name, retaining repeated RDN values.
                    labels = {
                        "common_name": "CN",
                        "country": "C",
                        "organization": "O",
                        "organizational_unit": "OU",
                        "province": "ST",
                        "locality": "L",
                        "email_address": "emailAddress",
                    }
                    components = []
                    for field, label in labels.items():
                        for value in dn.get(field) or []:
                            escaped = re.sub(r'([,+=<>#;"\\])', r"\\\1", str(value))
                            if escaped.startswith(" "):
                                escaped = "\\" + escaped
                            if escaped.endswith(" "):
                                escaped = escaped[:-1] + "\\ "
                            components.append(f"{label}={escaped}")
                    self.add(cert, side, ",".join(components))
            san = (tls.get("extensions") or {}).get("subject_alt_name") or {}
            for field, relation in (
                ("dns", "dns_names"),
                ("ipv4", "ip"),
                ("ipv6", "ip"),
                ("email", "email"),
                ("uri", "uri"),
            ):
                self.add(cert, relation, san.get(field))
            # Fingerprint-only and issuer-only objects are valid; TLS handshake-only data stays in modat-service.
            if any(a.object_relation in cert._definition["requiredOneOf"] for a in cert.attributes):
                self.put(cert, service.uuid, "used-by")
        fingerprints = data.get("fingerprints") or {}
        for kind, item in [("os", fingerprints.get("os")), ("service", fingerprints.get("service"))] + [
            ("technology", t) for t in fingerprints.get("technologies", [])
        ]:
            if not isinstance(item, dict) or not (item.get("product") or item.get("name")):
                continue
            software = MISPObject("software", strict=True)
            software.comment = f"MODAT {kind} fingerprint"
            self.add(software, "name", item.get("product") or item.get("name"))
            self.add(software, "version", item.get("version"))
            self.put(software, service.uuid)
        for item in (data.get("http") or {}).get("files") or []:
            file_obj = MISPObject("file", strict=True)
            self.add(file_obj, "filename", item.get("path"))
            self.add(file_obj, "sha1", item.get("sha1"))
            self.add(file_obj, "sha256", item.get("sha256"))
            self.add(file_obj, "text", f"MODAT category: {item['category']}" if item.get("category") else None)
            if any(a.object_relation in ("filename", "sha1", "sha256") for a in file_obj.attributes):
                self.put(file_obj, service.uuid)
        self.vulnerabilities(data.get("cves"), service.uuid)

    def dns(self, data):
        if not isinstance(data, dict) or not data.get("fqdn") or not isinstance(data.get("records"), dict):
            raise ModatError("MODAT returned an invalid DNS zone.")
        fqdn = _domain(data["fqdn"])
        if fqdn in self.zones:
            return
        self.zones.add(fqdn)
        for rrtype, records in data["records"].items():
            if not isinstance(records, list):
                raise ModatError("MODAT returned invalid DNS records.")
            for record in records:
                if not isinstance(record, dict):
                    raise ModatError("MODAT returned an invalid DNS record.")
                obj = self.custom("modat-dns-record")
                self.add(obj, "fqdn", fqdn)
                self.add(obj, "rrtype", rrtype.upper())
                for key, value in record.items():
                    relation = key.replace("_", "-")
                    if relation in obj._definition["attributes"] and key != "raw-json":
                        self.add(obj, relation, value)
                self.raw(
                    obj,
                    {
                        "fqdn": fqdn,
                        "rrtype": rrtype,
                        "record": record,
                        "discovered_at": data.get("discovered_at"),
                        "modified_at": data.get("modified_at"),
                    },
                )
                observation = self.put(obj)
                self.infrastructure(record, observation.uuid)
                if rrtype in ("a", "aaaa") and record.get("ip"):
                    domain_ip = MISPObject("domain-ip", strict=True)
                    self.add(domain_ip, "domain", fqdn)
                    self.add(domain_ip, "ip", record["ip"])
                    self.add(domain_ip, "first-seen", record.get("created_at"))
                    # deleted_at is lifecycle state, not the last observation time.
                    self.put(domain_ip, observation.uuid, "derived-from")
                # Preserve original DNS target notation, including root '.' and trailing dots.
                standard = {
                    "a": ("a-record", "ip"),
                    "aaaa": ("aaaa-record", "ip"),
                    "cname": ("cname-record", "cname"),
                    "mx": ("mx-record", "host"),
                    "ns": ("ns-record", "ns"),
                    "txt": ("txt-record", "value"),
                }
                if rrtype in standard:
                    relation, key = standard[rrtype]
                    if record.get(key):
                        dns = MISPObject("dns-record", strict=True)
                        self.add(dns, "queried-domain", fqdn)
                        self.add(dns, relation, record[key])
                        self.put(dns, observation.uuid, "derived-from")

    def result(self):
        event = json.loads(self.event.to_json())
        return {"results": {key: event.get(key, []) for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    client = None
    stage = "module request"
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModatError("Request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(k in attribute for k in ("type", "value", "uuid")):
            raise ModatError("Provide an attribute with type, value and uuid.")
        if not isinstance(attribute["type"], str) or not isinstance(attribute["value"], (str, int)):
            raise ModatError("Attribute type and value must be strings (numeric values are also accepted).")
        stage = "input attribute"
        UUID(str(attribute["uuid"]))
        config = request.get("config") or {}
        if not isinstance(config, dict) or not isinstance(config.get("apikey"), str) or not config["apikey"].strip():
            raise ModatError("Provide a MODAT API key in config.apikey.")
        limit = _integer(config, "max_results", DEFAULT_CONFIG["max_results"], 1, 1000)
        page_size = _integer(config, "page_size", DEFAULT_CONFIG["page_size"], 10, 100)
        timeout = _integer(config, "timeout", DEFAULT_CONFIG["timeout"], 1, 120)
        include_dns = _boolean(config, "include_dns", DEFAULT_CONFIG["include_dns"])
        reverse_dns = _boolean(config, "reverse_dns", DEFAULT_CONFIG["reverse_dns"])
        ip, query, zone = build_query(attribute)
        if query and len(query) > 2000:
            raise ModatError("Query exceeds the API's 2000-character limit.")
        parser = ModatParser(attribute)
        stage = "MODAT client configuration"
        client = ModatClient(config["apikey"].strip(), timeout)
        if ip:
            stage = "MODAT host lookup"
            with _subscription_access("host lookup"):
                data = client.request(f"/host/{quote(ip, safe='')}/v1")
                if data is not None:
                    if not isinstance(data.get("data"), dict):
                        raise ModatError("MODAT returned invalid host details.")
                    stage = "MODAT host data"
                    parser.host(data["data"])
        else:
            stage = "MODAT service search"
            with _subscription_access("service search"):
                for row in client.search("/service/search/v1", query, limit, page_size):
                    if not isinstance(row.get("service"), dict):
                        raise ModatError("MODAT returned an invalid service search record.")
                    stage = "MODAT service data"
                    parser.host(row)
        zones = [zone] if include_dns and zone else []
        if include_dns and reverse_dns and ip:
            stage = "MODAT reverse DNS search"
            with _subscription_access("reverse DNS search"):
                rrtype = "a" if ipaddress.ip_address(ip).version == 4 else "aaaa"
                for row in client.search("/dns/search/v1", _term((f"{rrtype}.ip",), ip), limit, min(page_size, 100)):
                    if not isinstance(row.get("fqdn"), str):
                        raise ModatError("MODAT returned an invalid DNS search record.")
                    zones.append(_domain(row["fqdn"]))
        for fqdn in dict.fromkeys(zones):
            stage = "MODAT DNS zone lookup"
            with _subscription_access("DNS zone lookup"):
                data = client.request(f"/dns/zones/{quote(fqdn, safe='')}/v1")
                if data is not None:
                    stage = "MODAT DNS zone data"
                    parser.dns(data)
        if client.permission_denied and not parser.event.objects:
            raise ModatPermissionError(
                "MODAT subscription denied one or more endpoints (HTTP 403), and no enrichment data was available."
            )
        stage = "MISP enrichment output"
        return parser.result()
    except ModatError as exc:
        return {"error": str(exc)}
    except requests.RequestException:
        # Exceptions may contain request headers or API response bodies; do not echo them.
        return {"error": "Unable to reach MODAT (network error or timeout)."}
    except (ValueError, TypeError, KeyError, AttributeError, PyMISPError) as exc:
        # Only identify the stage and exception class: exception messages may contain response data.
        LOGGER.warning("MODAT enrichment failed during %s (%s).", stage, type(exc).__name__)
        return {"error": f"Unable to process {stage} ({type(exc).__name__})."}
    finally:
        if client is not None:
            client.session.close()


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
