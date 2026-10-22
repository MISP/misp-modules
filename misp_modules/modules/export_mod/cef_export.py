import base64
import ipaddress
import json

misperrors = {"error": "Error"}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "2",
    "author": "Hannah Ward",
    "description": "Module to export a MISP event in CEF format.",
    "module-type": ["export"],
    "name": "CEF Export",
    "logo": "",
    "requirements": [],
    "features": (
        "Exports supported event and object attributes as UTF-8 CEF file records, with standard escaping and field"
        " validation. IPv6 address records use CEF:1; other records use CEF:0. Device settings and severity have"
        " defaults. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/cef_export.md) for mappings"
        " and compatibility changes."
    ),
    "references": [
        "https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf"
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Common Event Format file",
}

# config fields that your code expects from the site admin
moduleconfig = ["Default_Severity", "Device_Vendor", "Device_Product", "Device_Version"]

cefmapping = {
    "ip-src": "src",
    "ip-dst": "dst",
    "hostname": "dhost",
    "domain": "dhost",
    "md5": "fileHash",
    "sha1": "fileHash",
    "sha256": "fileHash",
    "url": "request",
}

mispattributes = {"input": list(cefmapping.keys())}
outputFileExtension = "cef"
responseType = "text/plain"
inputSource = ["event", "event-collection"]
DEFAULT_CONFIG = {
    "Default_Severity": 1,
    "Device_Vendor": "MISP",
    "Device_Product": "MISP",
    "Device_Version": 1,
}


def _text(value, name, limit, header=False):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be a non-empty string of at most {limit} characters.")
    value.encode("utf-8")
    if any(ord(char) < 32 and (header or char not in "\r\n\t") or ord(char) == 127 for char in value):
        raise ValueError(f"{name} contains an unsupported control character.")
    return value


def _header(value, name, limit):
    if type(value) is int:
        value = str(value)
    value = _text(value, name, limit, header=True)
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _extension(value):
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _severity(value):
    if type(value) is int and 0 <= value <= 10:
        return str(value)
    if isinstance(value, str):
        if value in ("Unknown", "Low", "Medium", "High", "Very-High"):
            return value
        if value.isascii() and value.isdecimal() and 0 <= int(value) <= 10:
            return str(int(value))
    raise ValueError("Default_Severity must be an integer from 0 to 10 or Unknown, Low, Medium, High, Very-High.")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _attributes(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(event, dict) for event in data):
        raise ValueError("data must be a MISP event or a list of events.")
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        # Legacy exports place collections alongside the Event metadata.
        collections = dict(event, **envelope)
        yield from _records(collections, "Attribute")
        for obj in _records(collections, "Object"):
            yield from _records(obj, "Attribute")


def _record(attr, device, severity):
    kind = attr.get("type")
    if not isinstance(kind, str) or kind not in cefmapping:
        return None
    key = cefmapping[kind]
    value = _text(attr.get("value"), kind, 255 if key == "fileHash" else 1023)
    cef_version = 0
    if key in ("src", "dst"):
        address = ipaddress.ip_address(value)
        if "%" in value:
            raise ValueError("Scoped IPv6 addresses cannot be represented in a CEF address field.")
        value = str(address)
        cef_version = int(address.version == 6)
    category = _text(attr.get("category", kind), "category", 512, header=True)
    name = _header(category, "category", 512)
    extension = [(key, value), ("cat", category)]
    if "timestamp" in attr:
        timestamp = attr["timestamp"]
        if not (type(timestamp) is int and timestamp >= 0) and not (
            isinstance(timestamp, str) and timestamp.isascii() and timestamp.isdecimal()
        ):
            raise ValueError("Attribute timestamp must be non-negative Unix seconds.")
        extension.extend(
            [("deviceCustomDate1", str(int(timestamp) * 1000)), ("deviceCustomDate1Label", "MISP attribute timestamp")]
        )
    fields = [f"CEF:{cef_version}", *device, kind, name, severity]
    return "|".join(fields) + "|" + " ".join(f"{key}={_extension(value)}" for key, value in extension)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("A request object with data is required.")
        supplied_config = request.get("config", {})
        if not isinstance(supplied_config, dict):
            raise ValueError("config must be an object.")
        config = {**DEFAULT_CONFIG, **supplied_config}
        severity = _severity(config["Default_Severity"])
        device = [
            _header(config[key], key, limit)
            for key, limit in (("Device_Vendor", 63), ("Device_Product", 63), ("Device_Version", 31))
        ]
        lines = []
        for attr in _attributes(request["data"]):
            line = _record(attr, device, severity)
            if line is not None:
                lines.append(line + "\n")
        return {"response": [], "data": base64.b64encode("".join(lines).encode("utf-8")).decode("ascii")}
    except (TypeError, ValueError) as error:
        return {"error": f"Unable to export CEF: {error}"}


def introspection():
    return {
        **mispattributes,
        "responseType": responseType,
        "outputFileExtension": outputFileExtension,
        "inputSource": inputSource,
    }


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
