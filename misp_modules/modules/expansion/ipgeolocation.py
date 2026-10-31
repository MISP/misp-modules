import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import check_input_attribute, standard_error_message

try:
    import maxminddb
except ImportError:  # only needed for the local database backend
    maxminddb = None

log = logging.getLogger("ipgeolocation")

mispattributes = {
    "input": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": 1,
    "author": "IPGeolocation.io",
    "description": (
        "An expansion and hover module to enrich an IP address with geolocation, ASN, company, threat intelligence"
        " (threat score, VPN, proxy, Tor, bot and spam signals) and abuse contact information from IPGeolocation.io,"
        " either through the API or from local IPGeolocation.io MMDB databases."
    ),
    "module-type": ["expansion", "hover"],
    "name": "IPGeolocation.io Lookup",
    "logo": "ipgeolocation.png",
    "requirements": ["An IPGeolocation.io API key, or IPGeolocation.io MMDB databases stored on the misp-modules host"],
    "features": (
        "The module takes an IP address attribute as input and answers from one of two sources:\n- `api_key`: the"
        " [IPGeolocation.io API](https://ipgeolocation.io/documentation/ip-location-api.html). Free plans return"
        " geolocation and ASN. Paid plans also return the company, threat intelligence (`include=security`), the abuse"
        " contact (`include=abuse`) and the hostname; the `include` setting chooses these modules (default"
        " `security,abuse,hostname`, `none` for the base lookup only). If the plan does not allow them, the module"
        " falls back to the base lookup. Results are cached in memory for `cache_ttl` seconds (default 3600) to save"
        " credits on repeated lookups such as hover.\n- `mmdb_paths`: comma-separated `.mmdb` files or directories of"
        " IPGeolocation.io databases: Location, Country, ISP, ASN, Company, Abuse Contact, Security (all versions),"
        " Residential Proxy and Hosting, or their combined editions. Names are returned in English. Lookups run locally"
        " and nothing is sent to IPGeolocation.io, which suits air-gapped instances and indicators that must not leave"
        " the organisation. Several databases are combined; for a field present in more than one, the first file in the"
        " list wins. Updated files are picked up automatically within a minute.\n\nWhen `mmdb_paths` is set, the API is"
        " never called."
    ),
    "references": [
        "https://ipgeolocation.io/documentation/ip-location-api.html",
        "https://ipgeolocation.io/ip-security-database.html",
    ],
    "input": "An IP address attribute (ip-src, ip-dst, ip-src|port, ip-dst|port or domain|ip).",
    "output": (
        "geolocation, asn and domain-ip objects, and an ipgeolocation-ip object with the threat score,"
        " anonymisation signals, company and abuse contact."
    ),
}
moduleconfig = ["api_key", "mmdb_paths", "include", "cache_ttl"]

API_URL = "https://api.ipgeolocation.io/v3/ipgeo"
DEFAULT_INCLUDE = "security,abuse,hostname"
DEFAULT_CACHE_TTL = 3600
CACHE_MAX_ENTRIES = 10000
MMDB_RECHECK_SECONDS = 60
TIMEOUT = (5, 30)
USER_AGENT = "misp-modules-ipgeolocation/1"

# Canonical field name -> (kind, paths). The paths cover the API v3 response and the layouts of the
# IPGeolocation.io MMDB databases; the first path holding a value of the right kind wins.
FIELDS = {
    "country_code": ("text", ("location.country_code2", "location.country.code2", "country.code2", "country_code2")),
    "country_name": ("text", ("location.country_name", "location.country.name", "country.name", "country_name")),
    "state_name": ("text", ("location.state_prov", "location.state.name", "state.name", "state_prov")),
    "city_name": ("text", ("location.city", "location.city.name", "city.name", "city")),
    "zip_code": ("text", ("location.zipcode", "location.zip_code", "zipcode", "zip_code", "postal_code")),
    "latitude": ("number", ("location.latitude", "location.coordinates.latitude", "latitude")),
    "longitude": ("number", ("location.longitude", "location.coordinates.longitude", "longitude")),
    "accuracy_radius": ("number", ("location.accuracy_radius", "accuracy_radius")),
    "route": ("text", ("network.route", "route")),
    "asn": ("text", ("asn.as_number", "network.asn.as_number", "asn.asn", "as_number", "asn")),
    "asn_name": ("text", ("asn.as_name", "network.asn.as_name", "as_name")),
    "asn_organization": ("text", ("asn.organization", "network.asn.organization", "as_organization")),
    "asn_country": ("text", ("asn.country", "asn.country_code", "network.asn.country", "asn_country", "as_country")),
    "company_name": ("text", ("company.name", "network.company.name", "company_name", "isp")),
    "company_domain": ("text", ("company.domain", "network.company.domain", "company_domain")),
    "company_type": ("text", ("company.type", "network.company.type", "company_type")),
    "hostname": ("text", ("hostname",)),
    "threat_score": ("number", ("security.threat_score", "threat_score")),
    "is_known_attacker": ("bool", ("security.is_known_attacker", "is_known_attacker")),
    "is_tor": ("bool", ("security.is_tor", "is_tor")),
    "is_vpn": ("bool", ("security.is_vpn", "is_vpn")),
    "is_proxy": ("bool", ("security.is_proxy", "is_proxy")),
    "is_residential_proxy": ("bool", ("security.is_residential_proxy", "is_residential_proxy")),
    "is_relay": ("bool", ("security.is_relay", "is_relay")),
    "is_anonymous": ("bool", ("security.is_anonymous", "is_anonymous")),
    "is_bot": ("bool", ("security.is_bot", "is_bot")),
    "is_spam": ("bool", ("security.is_spam", "is_spam")),
    "is_cloud_provider": ("bool", ("security.is_cloud_provider", "is_cloud_provider")),
    "is_known_good_bot": ("bool", ("security.is_known_good_bot", "is_known_good_bot")),
    "is_corporate_gateway": ("bool", ("security.is_corporate_gateway", "is_corporate_gateway")),
    "bot_operator": ("text", ("security.bot_operator_name", "bot_operator_name")),
    "bot_type": ("text", ("security.bot_type", "bot_type")),
    "bot_confidence": ("number", ("security.bot_confidence_score", "bot_confidence_score")),
    "bot_last_seen": ("text", ("security.bot_last_seen", "bot_last_seen")),
    "corporate_gateway_provider": (
        "text",
        ("security.corporate_gateway_provider_name", "corporate_gateway_provider_name"),
    ),
    "corporate_gateway_type": ("text", ("security.corporate_gateway_type", "corporate_gateway_type")),
    "vpn_providers": ("list", ("security.vpn_provider_names", "vpn_provider_names", "vpn_provider")),
    "vpn_confidence": ("number", ("security.vpn_confidence_score", "vpn_confidence_score")),
    "vpn_last_seen": ("text", ("security.vpn_last_seen", "vpn_last_seen")),
    "proxy_providers": ("list", ("security.proxy_provider_names", "proxy_provider_names", "proxy_provider")),
    "proxy_confidence": ("number", ("security.proxy_confidence_score", "proxy_confidence_score")),
    "proxy_last_seen": ("text", ("security.proxy_last_seen", "proxy_last_seen")),
    "relay_provider": ("text", ("security.relay_provider_name", "relay_provider_name", "relay_provider")),
    "cloud_provider": (
        "text",
        ("security.cloud_provider_name", "cloud_provider_name", "cloud_provider", "hosting_provider"),
    ),
    "abuse_name": ("text", ("abuse.name", "abuse_name")),
    "abuse_organization": ("text", ("abuse.organization", "abuse_organization")),
    # The API returns lists; the databases join several values with commas.
    "abuse_emails": ("csv", ("abuse.emails", "abuse.email", "abuse_email")),
    "abuse_phones": ("csv", ("abuse.phone_numbers", "abuse.phone", "abuse_phone")),
    "abuse_address": ("text", ("abuse.address", "abuse_address")),
    "abuse_country": ("text", ("abuse.country", "abuse.country_code", "abuse_country")),
    "abuse_route": ("text", ("abuse.route", "abuse.network", "abuse_route")),
}

_GEOLOCATION_MAPPING = (
    ("country_code", "countrycode"),
    ("country_name", "country"),
    ("state_name", "region"),
    ("city_name", "city"),
    ("zip_code", "zipcode"),
    ("latitude", "latitude"),
    ("longitude", "longitude"),
    ("accuracy_radius", "accuracy-radius"),
)
_FLAG_MAPPING = (
    ("is_known_attacker", "is-known-attacker"),
    ("is_tor", "is-tor"),
    ("is_vpn", "is-vpn"),
    ("is_proxy", "is-proxy"),
    ("is_residential_proxy", "is-residential-proxy"),
    ("is_relay", "is-relay"),
    ("is_anonymous", "is-anonymous"),
    ("is_bot", "is-bot"),
    ("is_spam", "is-spam"),
    ("is_cloud_provider", "is-cloud-provider"),
    ("is_known_good_bot", "is-known-good-bot"),
    ("is_corporate_gateway", "is-corporate-gateway"),
)
# The ipgeolocation-ip template (MISP/misp-objects), described here for PyMISP releases that do not ship it yet:
# MISP refuses to create an object without its meta-category and template UUID.
IPGEOLOCATION_TEMPLATE = {
    "uuid": "e1bde989-c8dd-49b1-a45b-b63698dbfcaa",
    "version": 1,
    "meta-category": "network",
    "description": (
        "IP address intelligence from IPGeolocation.io: threat score, anonymisation signals (VPN, proxy, Tor, relay),"
        " bot, spam and attacker flags, hosting provider, company and abuse contact."
    ),
}
# Types are given explicitly so the object can be built even where the template is not installed yet.
_IPGEOLOCATION_MAPPING = (
    ("threat_score", "threat-score", "integer"),
    ("vpn_providers", "vpn-provider", "text"),
    ("vpn_confidence", "vpn-confidence-score", "integer"),
    ("vpn_last_seen", "vpn-last-seen", "datetime"),
    ("proxy_providers", "proxy-provider", "text"),
    ("proxy_confidence", "proxy-confidence-score", "integer"),
    ("proxy_last_seen", "proxy-last-seen", "datetime"),
    ("relay_provider", "relay-provider", "text"),
    ("cloud_provider", "cloud-provider", "text"),
    ("bot_operator", "bot-operator", "text"),
    ("bot_type", "bot-type", "text"),
    ("bot_confidence", "bot-confidence-score", "integer"),
    ("bot_last_seen", "bot-last-seen", "datetime"),
    ("corporate_gateway_provider", "corporate-gateway-provider", "text"),
    ("corporate_gateway_type", "corporate-gateway-type", "text"),
    ("company_name", "company-name", "text"),
    ("company_domain", "company-domain", "domain"),
    ("company_type", "company-type", "text"),
    ("abuse_name", "abuse-name", "text"),
    ("abuse_organization", "abuse-organization", "text"),
    ("abuse_emails", "abuse-email", "email"),
    ("abuse_phones", "abuse-phone", "phone-number"),
    ("abuse_address", "abuse-address", "text"),
    ("abuse_country", "abuse-country", "text"),
    ("abuse_route", "abuse-route", "ip-src"),
)


class IPGeolocationError(Exception):
    """A lookup failed with a message that can be shown to the MISP user."""


class _TTLCache:
    """A small thread-safe LRU cache whose entries expire after a per-entry TTL."""

    def __init__(self, max_entries):
        self._max_entries = max_entries
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if expires < time.monotonic():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value, ttl):
        with self._lock:
            self._data[key] = (time.monotonic() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_entries:
                self._data.popitem(last=False)

    def clear(self):
        with self._lock:
            self._data.clear()


_cache = _TTLCache(CACHE_MAX_ENTRIES)
_session_lock = threading.Lock()
_http_session = None


def _session():
    global _http_session
    with _session_lock:
        if _http_session is None:
            retry = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=(502, 503, 504),
                allowed_methods=("GET",),
                raise_on_status=False,
            )
            session = requests.Session()
            session.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=32))
            session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
            _http_session = session
        return _http_session


def _dig(record, path):
    value = record
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _coerce(kind, value):
    """Return the value in the expected kind, or None when it is empty or of another shape."""
    if value is None or value == "" or value == [] or value == {}:
        return None
    if kind in ("list", "csv"):
        if isinstance(value, str):
            values = value.split(",") if kind == "csv" else [value]
            return [item.strip() for item in values if item.strip()] or None
        if isinstance(value, list):
            values = [item for item in value if isinstance(item, str) and item]
            return values or None
        return None
    if kind == "text" and isinstance(value, dict):
        value = value.get("en")  # databases store names per language: {"en": "Japan", "de": "Japan", ...}
        if not value:
            return None
    if isinstance(value, (dict, list)):
        return None
    if kind == "bool":
        if isinstance(value, str):
            return {"true": True, "1": True, "false": False, "0": False}.get(value.lower())
        return value if isinstance(value, bool) else None
    if kind == "number":
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)  # some databases store whole numbers, such as AS numbers, as doubles
    return str(value)


def _expand(record, database_type):
    """Map the single-purpose and older database layouts onto the fields of the current Security database."""
    record = dict(record)
    kind = database_type.lower()
    if "residential" in kind:  # Residential Proxy database: {"proxy_provider": ..., "last_seen": ...}
        record.setdefault("is_residential_proxy", True)
        record.setdefault("is_proxy", True)
        record.setdefault("proxy_last_seen", record.get("last_seen"))
    elif "hosting" in kind:  # IP Hosting database: {"hosting_provider": ...}
        record.setdefault("is_cloud_provider", True)
    if str(record.get("proxy_type", "")).upper() == "VPN" and "is_vpn" not in record:
        # The first Security database has no is_vpn: VPN exits are proxies of type VPN, named in proxy_provider.
        record["is_vpn"] = True
        record.setdefault("vpn_provider_names", record.pop("proxy_provider", None))
    return record


def normalize(records):
    """Map one or more raw records (API response or MMDB records) to the canonical fields.

    Records are tried in order, so with several MMDB files the first one holding a field wins.
    """
    result = {}
    for field, (kind, paths) in FIELDS.items():
        for record in records:
            value = next(
                (v for v in (_coerce(kind, _dig(record, path)) for path in paths) if v is not None),
                None,
            )
            if value is not None:
                result[field] = value
                break
    if "asn" in result:
        number = result["asn"].upper().removeprefix("AS")
        if number.isdigit():
            result["asn"] = number
        else:
            del result["asn"]
    return result


def _redact(text):
    return re.sub(r"(apiKey=)[^&\s'\"]+", r"\1***", text)


def _api_error(response):
    try:
        message = response.json().get("message")
    except ValueError:
        message = None
    return message or response.reason or "unknown error"


def _api_get(ip, api_key, include):
    params = {"apiKey": api_key, "ip": ip}
    if include:
        params["include"] = include
    try:
        return _session().get(API_URL, params=params, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise IPGeolocationError(f"Could not reach the IPGeolocation.io API: {_redact(str(e))}")


def lookup_api(ip, api_key, include, cache_ttl):
    # Set when the plan rejected the optional modules, so later lookups skip them for an hour.
    if include and _cache.get(("no-include", api_key)):
        include = ""
    cache_key = ("api", api_key, include, ip)
    if cache_ttl > 0:
        cached = _cache.get(cache_key)
        if cached is not None:
            return cached

    response = _api_get(ip, api_key, include)
    if response.status_code == 401 and include:
        # Free plans reject the optional modules; retry with the base lookup they do allow.
        retry = _api_get(ip, api_key, "")
        if retry.status_code == 200:
            log.info("The IPGeolocation.io plan does not include `%s`; using the base lookup.", include)
            _cache.set(("no-include", api_key), True, DEFAULT_CACHE_TTL)
            include = ""
            cache_key = ("api", api_key, include, ip)
        response = retry
    if response.status_code == 423:
        raise IPGeolocationError(f"{ip} is a bogon or private address and cannot be looked up.")
    if response.status_code == 404:
        raise IPGeolocationError(f"{ip} is not in the IPGeolocation.io database.")
    if response.status_code != 200:
        raise IPGeolocationError(f"IPGeolocation.io API error {response.status_code}: {_api_error(response)}")
    try:
        data = response.json()
    except ValueError:
        raise IPGeolocationError("The IPGeolocation.io API returned a response that is not JSON.")

    result = (normalize([data]), "API")
    if cache_ttl > 0:
        _cache.set(cache_key, result, cache_ttl)
    return result


class _MMDBSet:
    """The databases behind one `mmdb_paths` setting.

    Each file is opened once and memory mapped, so lookups are local and cheap, and reopened when it
    changes on disk. A replaced reader is not closed: lookups still using it finish on the old file.
    """

    def __init__(self, setting):
        self.entries = [entry.strip() for entry in setting.split(",") if entry.strip()]
        self._readers = {}
        self._checked = 0.0
        self._lock = threading.Lock()

    def _files(self):
        files = []
        for entry in self.entries:
            if os.path.isdir(entry):
                files.extend(os.path.join(entry, name) for name in sorted(os.listdir(entry)) if name.endswith(".mmdb"))
            else:
                files.append(entry)
        return files

    def _refresh(self):
        readers = {}
        for path in self._files():
            try:
                stat = os.stat(path)
            except OSError as e:
                raise IPGeolocationError(f"Cannot read the IPGeolocation.io database {path}: {e.strerror}")
            signature = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
            current = self._readers.get(path)
            if current is not None and current[0] == signature:
                readers[path] = current
                continue
            try:
                reader = maxminddb.open_database(path, maxminddb.MODE_AUTO)
            except (OSError, ValueError, maxminddb.InvalidDatabaseError) as e:
                raise IPGeolocationError(f"Cannot open the IPGeolocation.io database {path}: {e}")
            readers[path] = (signature, reader)
        if not readers:
            raise IPGeolocationError("No .mmdb files found in mmdb_paths.")
        self._readers = readers

    def readers(self):
        with self._lock:
            if not self._readers or time.monotonic() - self._checked > MMDB_RECHECK_SECONDS:
                self._refresh()
                self._checked = time.monotonic()
            return [(path, reader) for path, (_, reader) in self._readers.items()]


_mmdb_sets = {}
_mmdb_lock = threading.Lock()


def _describe(path, reader):
    metadata = reader.metadata()
    built = datetime.fromtimestamp(metadata.build_epoch, tz=timezone.utc).strftime("%Y-%m-%d")
    return f"{os.path.basename(path)} ({metadata.database_type}, built {built})"


def lookup_mmdb(ip, setting):
    if maxminddb is None:
        raise IPGeolocationError("The maxminddb Python package is required to read IPGeolocation.io databases.")
    with _mmdb_lock:
        mmdb_set = _mmdb_sets.get(setting)
        if mmdb_set is None:
            mmdb_set = _mmdb_sets[setting] = _MMDBSet(setting)
    records, sources = [], []
    for path, reader in mmdb_set.readers():
        try:
            record = reader.get(ip)
        except ValueError:  # an IPv6 address looked up in an IPv4-only database
            continue
        if record:
            records.append(_expand(record, reader.metadata().database_type))
            sources.append(_describe(path, reader))
    if not records:
        raise IPGeolocationError(f"{ip} is not in the configured IPGeolocation.io databases.")
    return normalize(records), ", ".join(sources)


def _input_ip(attribute):
    value = attribute["value"]
    if attribute["type"] == "domain|ip":
        value = value.split("|")[1]
    elif attribute["type"].endswith("|port"):
        value = value.rsplit("|", 1)[0]
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _add(misp_object, relation, value, attribute_type=None):
    kwargs = {"type": attribute_type} if attribute_type else {}
    for item in value if isinstance(value, list) else [value]:
        if isinstance(item, float) and attribute_type == "integer":
            item = int(item)
        misp_object.add_attribute(relation, value=item, **kwargs)


def build_results(attribute, data, ip, source):
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)
    comment = f"IPGeolocation.io {source}"

    if any(field in data for field, _ in _GEOLOCATION_MAPPING):
        geolocation = MISPObject("geolocation")
        geolocation.comment = comment
        for field, relation in _GEOLOCATION_MAPPING:
            if field in data:
                _add(geolocation, relation, data[field])
        geolocation.add_reference(input_attribute.uuid, "describes")
        misp_event.add_object(geolocation)

    if "asn" in data:
        asn = MISPObject("asn")
        asn.comment = comment
        _add(asn, "asn", data["asn"])
        description = data.get("asn_organization") or data.get("asn_name")
        if description:
            _add(asn, "description", description)
        if "asn_country" in data:
            _add(asn, "country", data["asn_country"])
        if "route" in data:
            _add(asn, "subnet-announced", data["route"])
        asn.add_reference(input_attribute.uuid, "includes")
        misp_event.add_object(asn)

    hostname = data.get("hostname")
    if hostname and hostname != str(ip):
        domain_ip = MISPObject("domain-ip")
        domain_ip.comment = comment
        _add(domain_ip, "hostname", hostname)
        _add(domain_ip, "ip", str(ip))
        domain_ip.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(domain_ip)

    flags = [relation for field, relation in _FLAG_MAPPING if data.get(field) is True]
    # A confidence score of 0 only restates that the flag is false.
    details = [
        entry
        for entry in _IPGEOLOCATION_MAPPING
        if entry[0] in data and not (entry[0].endswith("_confidence") and data[entry[0]] == 0)
    ]
    if flags or details:
        intelligence = MISPObject("ipgeolocation-ip")
        if getattr(intelligence, "template_uuid", None) is None:
            intelligence.template_uuid = IPGEOLOCATION_TEMPLATE["uuid"]
            intelligence.template_version = IPGEOLOCATION_TEMPLATE["version"]
            intelligence.description = IPGEOLOCATION_TEMPLATE["description"]
            setattr(intelligence, "meta-category", IPGEOLOCATION_TEMPLATE["meta-category"])
        intelligence.comment = comment
        _add(intelligence, "ip", str(ip), "ip-src")
        for relation in flags:
            _add(intelligence, relation, 1, "boolean")
        for field, relation, attribute_type in details:
            _add(intelligence, relation, data[field], attribute_type)
        intelligence.add_reference(input_attribute.uuid, "describes")
        misp_event.add_object(intelligence)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request.get("attribute")
    if not attribute or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    ip = _input_ip(attribute)
    if ip is None:
        return {"error": f"{attribute['value']} does not contain a valid IP address."}
    if not ip.is_global:
        return {"error": f"{ip} is a private or reserved address and cannot be looked up."}

    config = request.get("config") or {}
    try:
        if config.get("mmdb_paths"):
            data, source = lookup_mmdb(str(ip), config["mmdb_paths"])
        elif config.get("api_key"):
            include = (config.get("include") or DEFAULT_INCLUDE).replace(" ", "")
            if include.lower() == "none":
                include = ""
            cache_ttl = config.get("cache_ttl")
            try:
                cache_ttl = DEFAULT_CACHE_TTL if cache_ttl in (None, "") else int(cache_ttl)
            except ValueError:
                return {"error": "cache_ttl must be a number of seconds."}
            data, source = lookup_api(str(ip), config["api_key"], include, cache_ttl)
        else:
            return {"error": "Set api_key to use the IPGeolocation.io API, or mmdb_paths to use local databases."}
    except IPGeolocationError as e:
        return {"error": str(e)}
    return build_results(attribute, data, ip, source)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
