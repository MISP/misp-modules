"""Extract legacy OpenIOC files without MISP's removed core importer."""

import base64
import json
import re
from io import BytesIO
from ipaddress import ip_interface
from xml.etree import ElementTree as ET

from pymisp import MISPEvent
from pymisp.exceptions import PyMISPError

userConfig = {
    "not save ioc": {
        "type": "Boolean",
        "message": "Do not retain the original IOC file as an attachment",
    },
    "default tag": {
        "type": "String",
        "message": "Comma-separated tags to apply to imported attributes (e.g. tlp:clear)",
        "validation": "0",
    },
}

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP Format"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.2",
    "author": "Raphaël Vinot, Alexandre Dulaunoy",
    "description": "Import legacy OpenIOC 1.0 and 1.1 files into MISP.",
    "module-type": ["import"],
    "name": "OpenIOC Import",
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "A backup import path for legacy .ioc files after removal of the core OpenIOC importer in MISP 3.0. "
        "Upload an OpenIOC 1.0 (ioc/definition) or 1.1 (OpenIOC/criteria) XML file through Import from modules, "
        "using openiocimport. Common file, network, email, registry, mutex and service fields become MISP attributes; "
        "unmapped fields are retained as other attributes. The original XML is attached by default; the existing "
        "not save ioc and default tag options are supported. XML DTDs and custom entities are rejected. "
        "This extracts observables, rather than evaluating OpenIOC rules: conditions, negation, case sensitivity, "
        "item IDs and the AND/OR group path are recorded in attribute comments. All attributes have to_ids=false "
        "for review. Correlation is disabled for grouped AND terms, non-exact or negated conditions and unmapped "
        "fields, so these are not treated as independent exact indicators. Keep the attachment for the full rule."
    ),
    "references": ["https://github.com/mandiant/ioc_writer"],
    "input": "OpenIOC 1.0 or 1.1 XML (.ioc or .xml), including namespace-free legacy files",
    "output": "MISP Event attributes and the optional original IOC attachment",
}

moduleconfig = []

# Unknown paths remain non-correlating 'other' attributes with their path intact.
_FIELD_TYPES = {
    "FileItem/FileName": "filename",
    "FileItem/FilePath": "filename",
    "FileItem/FullPath": "filename",
    "FileItem/Md5sum": "md5",
    "FileItem/Sha1sum": "sha1",
    "FileItem/Sha256sum": "sha256",
    "FileItem/SizeInBytes": "size-in-bytes",
    "FileItem/StringList/string": "pattern-in-file",
    "FileItem/PEInfo/Sections/Section/Name": "pattern-in-memory",
    "DnsEntryItem/Host": "domain",
    "DnsEntryItem/RecordName": "domain",
    "Network/DNS": "domain",
    "Network/URI": "uri",
    "Network/String": "url",
    "Network/IPRange": "ip-dst",
    "Network/UserAgent": "user-agent",
    "PortItem/localIP": "ip-src",
    "PortItem/remoteIP": "ip-dst",
    "PortItem/remotePort": "port",
    "PortItem/localPort": "port",
    "RouteEntryItem/Destination/IP": "ip-dst",
    "RouteEntryItem/Destination/string": "hostname",
    "UrlHistoryItem/URL": "url",
    "UrlHistoryItem/HostName": "hostname",
    "CookieHistoryItem/HostName": "hostname",
    "FormHistoryItem/HostName": "hostname",
    "SystemInfoItem/HostName": "hostname",
    "Email/From": "email-src",
    "Email/To": "email-dst",
    "Email/Subject": "email-subject",
    "Email/Body": "email-body",
    "Email/Attachment/Name": "email-attachment",
    "RegistryItem/Path": "regkey",
    "RegistryItem/KeyPath": "regkey",
    "RegistryItem/Text": "text",
    "RegistryItem/Value": "text",
    "RegistryItem/ValueName": "text",
    "ProcessItem/name": "filename",
    "ProcessItem/path": "filename",
    "ProcessItem/arguments": "text",
    "ProcessItem/Mutex": "mutex",
    "ProcessItem/NamedPipe": "named pipe",
    "DriverItem/DriverName": "filename",
    "DriverItem/DeviceItem/AttachedToDriverName": "filename",
    "ServiceItem/name": "windows-service-name",
    "ServiceItem/descriptiveName": "windows-service-displayname",
    "ServiceItem/serviceDLL": "filename",
    "ServiceItem/serviceDLLmd5sum": "md5",
    "ServiceItem/serviceDLLsha1sum": "sha1",
    "ServiceItem/serviceDLLsha256sum": "sha256",
    "TaskItem/Name": "windows-scheduled-task",
    "Snort/Snort": "snort",
    "Yara/Yara": "yara",
}
_FIELD_TYPES = {path.lower(): attribute_type for path, attribute_type in _FIELD_TYPES.items()}
_NAMESPACES = {"", "http://schemas.mandiant.com/2010/ioc", "http://openioc.org/schemas/OpenIOC_1.1"}


class _OpenIOCTreeBuilder(ET.TreeBuilder):
    def doctype(self, name, pubid, system):
        # Reject at parser level, including UTF-16 input and internal entities.
        raise ValueError("XML document type declarations and entities are not allowed.")


def _name(element):
    return element.tag.rsplit("}", 1)[-1]


def _child(element, name):
    return next((child for child in element if _name(child) == name), None)


def _text(element):
    return "" if element is None else "".join(element.itertext())


def _enabled(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _is_port(value):
    return bool(re.fullmatch(r"[0-9]+", value) and 1 <= int(value) <= 65535)


def _mapped_value(attribute_type, value):
    """Keep patterns and partial values out of types with strict MISP validation."""
    if attribute_type in {"md5", "sha1", "sha256"}:
        length = {"md5": 32, "sha1": 40, "sha256": 64}[attribute_type]
        if not re.fullmatch(r"[a-fA-F0-9]{%d}" % length, value):
            return "other", value
    elif attribute_type in {"ip-src", "ip-dst"}:
        try:
            ip_interface(value)
        except ValueError:
            # Older producers sometimes store IPv4:port in an IP context.
            address, separator, port = value.rpartition(":")
            try:
                if not separator or not _is_port(port):
                    return "other", value
                ip_interface(address)
            except ValueError:
                return "other", value
            return attribute_type + "|port", address + "|" + port
    elif attribute_type == "port":
        if not _is_port(value):
            return "other", value
    elif attribute_type == "size-in-bytes":
        if not re.fullmatch(r"[0-9]+", value):
            return "other", value
    # PyMISP checks attribute structure, not these server-side value rules.
    # Match MISP's strict string validators so invalid patterns are not lost
    # when the result is imported by the server.
    elif attribute_type in {"domain", "hostname"}:
        if not re.fullmatch(r"[A-Za-z0-9._-]+\.[A-Za-z0-9-]{2,}", value):
            return "other", value
    elif attribute_type in {"email-src", "email-dst"}:
        if not re.fullmatch(r".[^\s]*@.*\..*", value):
            return "other", value
    elif attribute_type in {"windows-service-name", "windows-service-displayname"}:
        if len(value.encode("utf-8")) > 256 or "/" in value or "\\" in value:
            return "other", value
    return attribute_type, value


def _indicators(criteria):
    """Yield leaves and their group paths without interpreting the Boolean rule."""
    stack = [(criteria, ())]
    while stack:
        node, groups = stack.pop()
        name = _name(node)
        if name == "IndicatorItem":
            yield node, groups
            continue
        if name == "Indicator":
            groups += ((node.get("operator", "unknown").upper(), node.get("id", "")),)
        stack.extend((child, groups) for child in reversed(list(node)))


def _add_indicator(event, item, groups):
    context = _child(item, "Context")
    content = _child(item, "Content")
    if context is None or not context.get("search") or content is None or not _text(content).strip():
        raise ValueError("Each IndicatorItem must contain a Context search path and non-empty Content.")
    search = context.get("search")
    value = _text(content)
    condition = item.get("condition", "unknown")
    search_key = search.lower()
    if search_key == "routeentryitem/destination":
        search_key += "/" + content.get("type", "").lower()
    attribute_type, value = _mapped_value(_FIELD_TYPES.get(search_key, "other"), value)
    exact = (
        condition.lower() == "is"
        and item.get("negate", "false").lower() in {"false", "0"}
        and all(operator == "OR" for operator, _ in groups)
        and attribute_type not in {"other", "text"}
    )
    parts = [f"OpenIOC: {search}", f"condition={condition}"]
    parts.extend(f"{key}={value}" for key, value in item.attrib.items() if key != "condition")
    parts.extend(f"Context {key}={value}" for key, value in context.attrib.items() if key != "search")
    parts.append(f"Content type={content.get('type', 'unknown')}")
    if groups:
        parts.append("logic=" + " > ".join(f"{operator}[{group_id}]" for operator, group_id in groups))
    comment = _text(_child(item, "Comment"))
    if comment:
        parts.append(comment)
    attributes = {"to_ids": False, "disable_correlation": not exact, "comment": "; ".join(parts)}
    try:
        event.add_attribute(attribute_type, value, **attributes)
    except PyMISPError:
        # Retain an observable even when PyMISP cannot represent its mapped type.
        attributes["disable_correlation"] = True
        event.add_attribute("other", value, **attributes)


def _parse(package):
    root = ET.fromstring(package, parser=ET.XMLParser(target=_OpenIOCTreeBuilder()))
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    if _name(root) not in {"ioc", "OpenIOC"} or namespace not in _NAMESPACES:
        raise ValueError("Expected an OpenIOC 1.0 or 1.1 document.")
    criteria = _child(root, "definition" if _name(root) == "ioc" else "criteria")
    if criteria is None:
        raise ValueError("The OpenIOC document has no definition or criteria.")
    metadata = _child(root, "metadata")
    if metadata is None:
        metadata = root
    event = MISPEvent()
    event.info = _text(_child(metadata, "short_description")) or "Legacy OpenIOC import"
    details = [f"OpenIOC id={root.get('id', 'unknown')}"]
    for field in ("description", "authored_by", "authored_date"):
        value = _text(_child(metadata, field))
        if value:
            details.append(f"{field}: {value}")
    event.add_attribute("comment", "\n".join(details), to_ids=False, disable_correlation=True)
    count = 0
    for item, groups in _indicators(criteria):
        _add_indicator(event, item, groups)
        count += 1
    if not count:
        raise ValueError("The OpenIOC document contains no IndicatorItem elements.")
    return event


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("data"), str):
            raise ValueError("The request must contain a base64-encoded data string.")
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ValueError("The import configuration must be an object.")
        tags = config.get("default tag") or ""
        if not isinstance(tags, str):
            raise ValueError("The default tag option must be a comma-separated string.")
        package = base64.b64decode(b"".join(request["data"].encode("ascii").split()), validate=True)
        if not package:
            raise ValueError("The uploaded IOC file is empty.")
        event = _parse(package)
        if not _enabled(config.get("not save ioc", False)):
            filename = request.get("filename") or "openioc.ioc"
            if not isinstance(filename, str):
                raise ValueError("The filename must be a string.")
            event.add_attribute(
                "attachment",
                filename,
                data=BytesIO(package),
                category="Support Tool",
                to_ids=False,
                disable_correlation=True,
            )
        for attribute in event.attributes:
            for tag in tags.split(","):
                if tag.strip():
                    attribute.add_tag(tag.strip())
        return {"results": json.loads(event.to_json())}
    except (ValueError, TypeError, LookupError, ET.ParseError, PyMISPError) as error:
        return {"error": f"Unable to import OpenIOC: {error}"}


def introspection():
    return {**mispattributes, "userConfig": userConfig}


def version():
    return {**moduleinfo, "config": moduleconfig}
