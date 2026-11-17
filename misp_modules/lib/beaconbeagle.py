"""BeaconBeagle API transport and lossless, deterministic MISP conversion."""

import base64
import datetime as dt
import json
import math
import re
from ipaddress import ip_address
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid5

import requests
from pymisp import MISPObject

API = "https://beaconbeagle.com/api/v1/"
NAMESPACE = UUID("5b6e5d32-98a3-55ba-95ea-d4ae4bd695d4")
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
HASH = re.compile(r"^[a-fA-F0-9]{64}$")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def identity(*parts):
    return str(uuid5(NAMESPACE, canonical(parts)))


def integer(value, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("Expected a positive integer")
    result = int(value)
    if not 1 <= result <= maximum:
        raise ValueError(f"Expected an integer between 1 and {maximum}")
    return result


class Client:
    def __init__(self, check_cancel=lambda: None):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "MISP-modules/BeaconBeagle"
        self.check_cancel = check_cancel

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def get(self, path, params=None, missing=False):
        return self.request("GET", path, params=params, missing=missing)

    def post(self, path, body):
        return self.request("POST", path, body=body)

    def request(self, method, path, params=None, body=None, missing=False):
        self.check_cancel()
        try:
            with self.session.request(
                method, API + path, params=params, json=body, timeout=(5, 30), stream=True, allow_redirects=False
            ) as response:
                if missing and response.status_code == 404:
                    return None
                if response.status_code != 200:
                    raise ValueError(f"BeaconBeagle returned HTTP {response.status_code}")
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    self.check_cancel()
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ValueError("BeaconBeagle response size budget exceeded")
                    chunks.append(chunk)
                result = json.loads(b"".join(chunks))
        except requests.RequestException:
            raise ValueError("BeaconBeagle request failed or timed out") from None
        if not isinstance(result, dict):
            raise ValueError("BeaconBeagle response must be an object")
        return result

    def pages(self, path, params=None, key="items", page_size=100):
        offset = 0
        while True:
            data = self.get(path, {**(params or {}), "limit": page_size, "offset": offset})
            items, total = data.get(key), data.get("total")
            if not isinstance(items, list) or type(total) is not int or total < 0:
                raise ValueError("Invalid BeaconBeagle page")
            if not items:
                if offset < total:
                    raise ValueError("BeaconBeagle pagination stopped before the reported total")
                return
            yield from items
            offset += len(items)
            if offset >= total:
                return


def path_key(value):
    return quote(value, safe="")


def host(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid BeaconBeagle host")
    value = value.strip()
    try:
        return "ip-dst", str(ip_address(value))
    except ValueError:
        value = value.rstrip(".").encode("idna").decode().lower()
        if len(value) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
        ):
            raise ValueError("Invalid BeaconBeagle hostname")
        return "domain", value


def timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("Invalid BeaconBeagle observation timestamp")
    return dt.datetime.fromtimestamp(value, dt.timezone.utc)


def normalized(kind, data):
    """Sort unordered API collections; configuration instruction arrays retain order."""
    data = json.loads(canonical(data))
    if kind == "configs":
        if not isinstance(data.get("locations"), list) or not all(isinstance(v, dict) for v in data["locations"]):
            raise ValueError("Invalid BeaconBeagle configuration locations")
        data["locations"] = sorted(data.get("locations", []), key=canonical)
    if kind == "c2":
        for key in ("IPs", "Protocols", "Ports", "SubmitURIs", "Paths", "URLs"):
            if key in data:
                if not isinstance(data[key], list):
                    raise ValueError("Invalid BeaconBeagle C2 collection")
                data[key] = sorted(data[key], key=canonical)
        if not isinstance(data.get("Endpoints", {}), dict):
            raise ValueError("Invalid BeaconBeagle endpoints")
        for endpoint in data.get("Endpoints", {}).values():
            if not isinstance(endpoint, dict):
                raise ValueError("Invalid BeaconBeagle endpoint")
            for key in ("submituris", "paths", "urls", "seen_in"):
                if key in endpoint:
                    if not isinstance(endpoint[key], list):
                        raise ValueError("Invalid BeaconBeagle endpoint collection")
                    endpoint[key] = sorted(endpoint[key], key=canonical)
    if kind == "beacons":
        if not isinstance(data.get("ports", {}), dict):
            raise ValueError("Invalid BeaconBeagle ports")
        for architectures in data.get("ports", {}).values():
            if not isinstance(architectures, dict):
                raise ValueError("Invalid BeaconBeagle architectures")
            for entry in architectures.values():
                if not isinstance(entry, dict) or not isinstance(entry.get("versions", []), list):
                    raise ValueError("Invalid BeaconBeagle versions")
                if not all(isinstance(version, dict) for version in entry.get("versions", [])):
                    raise ValueError("Invalid BeaconBeagle version")
                entry["versions"] = sorted(entry.get("versions", []), key=canonical)
    return data


def convert(kind, key, data):
    """Return a feed event and source timestamp; raw JSON preserves every API field."""
    if kind not in ("configs", "beacons", "c2") or not isinstance(data, dict):
        raise ValueError("Invalid BeaconBeagle record")
    if kind == "configs" and (not HASH.fullmatch(key) or data.get("hash") != key):
        raise ValueError("Unexpected BeaconBeagle configuration hash")
    if kind == "beacons" and data.get("ip") != key:
        raise ValueError("Unexpected BeaconBeagle IP")
    if kind == "c2" and data.get("key") != key:
        raise ValueError("Unexpected BeaconBeagle C2 key")
    data = normalized(kind, data)
    event_uuid = identity("event-v1", kind, key)
    source_url = API + kind + "/" + path_key(key)
    observations = data.get("locations", []) if kind == "configs" else [data]
    if kind == "beacons":
        observations += [
            version
            for architectures in data.get("ports", {}).values()
            for entry in architectures.values()
            for version in entry.get("versions", [])
        ]
    times = [timestamp(item[name]) for item in observations for name in ("Firsttime", "lasttime") if name in item]
    latest = max(times) if times else dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    event = {
        "uuid": event_uuid,
        "info": f"BeaconBeagle {kind}: {key}",
        "date": latest.date().isoformat(),
        "published": True,
        "distribution": "0",
        "analysis": "2",
        "threat_level_id": "4",
        "Orgc": {"name": "BeaconBeagle", "uuid": identity("organisation")},
        "Attribute": [],
        "Object": [],
    }
    seen, object_index = set(), {}

    def attribute(attr_type, value, comment="BeaconBeagle observed infrastructure"):
        ident = identity(event_uuid, attr_type, value)
        if ident not in seen:
            seen.add(ident)
            event["Attribute"].append(
                {"uuid": ident, "type": attr_type, "value": value, "to_ids": False, "comment": comment}
            )

    def obj(name, discriminator, values, observation=None):
        result = MISPObject(name, strict=True)
        result.uuid = identity(event_uuid, name, discriminator)
        result.comment = source_url
        for relation, value in sorted(set(values), key=canonical):
            options = {}
            if observation:
                for field, api_field in (("first_seen", "Firsttime"), ("last_seen", "lasttime")):
                    if api_field in observation:
                        options[field] = timestamp(observation[api_field])
            result.add_attribute(
                relation, value=value, uuid=identity(result.uuid, relation, value), to_ids=False, **options
            )
        result = json.loads(result.to_json())
        previous = object_index.get(result["uuid"])
        if previous:
            for current, old in zip(result["Attribute"], previous["Attribute"]):
                for field, aggregate in (("first_seen", min), ("last_seen", max)):
                    times = [entry[field] for entry in (current, old) if field in entry]
                    if times:
                        current[field] = aggregate(times)
        object_index[result["uuid"]] = result

    def infrastructure(value, port=None, protocol=None, observation=None):
        attr_type, value = host(value)
        attribute(attr_type, value)
        values = [(attr_type, value)]
        if port is not None:
            # The beacon API also exposes metadata keys such as GEO and ASN as ports.
            if not re.fullmatch(r"[0-9]+", str(port)) or not 1 <= int(port) <= 65535:
                return
            values.append(("dst-port", str(int(port))))
        if protocol:
            values.append(("protocol", str(protocol)))
        obj("ip-port", [value, str(port), protocol], values, observation)

    attribute("link", source_url, "BeaconBeagle source API record")
    raw = {
        "uuid": identity(event_uuid, "raw"),
        "type": "attachment",
        "value": f"beaconbeagle-{kind}-{identity(key)}.json",
        "data": base64.b64encode(canonical(data).encode()).decode(),
        "to_ids": False,
        "disable_correlation": True,
        "comment": "Complete BeaconBeagle API record; configuration hashes are not sample hashes.",
    }
    event["Attribute"].append(raw)
    if kind == "configs":
        config = data.get("config")
        if not isinstance(config, dict) or not isinstance(data.get("locations"), list):
            raise ValueError("Invalid BeaconBeagle configuration")
        obj(
            "malware-config",
            key,
            [
                ("config", canonical(config)),
                ("format", "JSON"),
                ("description", f"Cobalt Strike configuration; BeaconBeagle hash {key}"),
            ],
        )
        for location in data["locations"]:
            infrastructure(
                str(ip_address(location["beacon_ip"])), location.get("beacon_port"), location.get("protocol"), location
            )
        settings = config.get("settings", {})
        if not isinstance(settings, dict):
            raise ValueError("Invalid BeaconBeagle settings")
        domains = settings.get("SETTING_DOMAINS", "")
        if not isinstance(domains, str):
            raise ValueError("Invalid BeaconBeagle C2 domains")
        # Alternating host, URI entries in the Cobalt Strike setting.
        for domain in domains.split(",")[::2]:
            if domain.strip():
                infrastructure(domain, settings.get("SETTING_PORT"), config.get("protocol"))
        if settings.get("SETTING_USERAGENT"):
            if not isinstance(settings["SETTING_USERAGENT"], str):
                raise ValueError("Invalid BeaconBeagle user agent")
            attribute("user-agent", settings["SETTING_USERAGENT"], "Cobalt Strike configured HTTP user agent")
    elif kind == "beacons":
        infrastructure(key, observation=data)
        for port, architectures in data.get("ports", {}).items():
            for entry in architectures.values():
                for version in entry.get("versions", []):
                    infrastructure(key, port, version.get("protocol"), version)
    else:
        for address in sorted(set(data.get("IPs", []) + ([data["Host"]] if data.get("Host") else []))):
            infrastructure(address, observation=data)
        for endpoint in data.get("Endpoints", {}).values():
            for address in data.get("IPs", []) or [data.get("Host", key)]:
                infrastructure(address, endpoint.get("port"), endpoint.get("protocol"), endpoint)
        for url in data.get("URLs", []):
            if not isinstance(url, str) or urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
                raise ValueError("Invalid BeaconBeagle C2 URL")
            attribute("url", url)
    for item in observations:
        if item.get("asn"):
            attribute("AS", "AS" + str(item["asn"]).removeprefix("AS"), "BeaconBeagle network ASN")
    # Duplicate versions/architectures can describe the same observed endpoint.
    event["Object"] = list(object_index.values())
    event["Object"].sort(key=lambda item: item["uuid"])
    event["Attribute"].sort(key=lambda item: item["uuid"])
    return event, int(latest.timestamp())
