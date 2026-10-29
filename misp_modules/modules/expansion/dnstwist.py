import idna
import ipaddress
import json
import re
import zipfile
from uuid import UUID
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError


class ModuleError(ValueError):
    """A diagnostic safe to show to the analyst."""


def _integer(config, key, default, maximum=100):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or (not 1 <= int(value) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(value)


def _enabled(config, key, default=False):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if str(value).lower() not in ("true", "false", "1", "0"):
        raise ModuleError(f"{key} must be true or false.")
    return str(value).lower() in ("true", "1")


def _normalise(kind, value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ModuleError("A nonempty string value is required.")
    value = value.strip()
    if kind in ("md5", "sha1", "sha256", "x509-fingerprint-sha256"):
        length = {"md5": 32, "sha1": 40}.get(kind, 64)
        if not re.fullmatch("[a-fA-F0-9]{%d}" % length, value):
            raise ModuleError("Invalid hash.")
        return value.lower()
    if kind in ("ip-src", "ip-dst"):
        return str(ipaddress.ip_address(value))
    if kind in ("domain", "hostname"):
        value = idna.encode(value.rstrip("."), uts46=True, transitional=False).decode("ascii").lower()
        if len(value) > 253 or not all(
            re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")
        ):
            raise ModuleError("Invalid DNS name.")
    if kind == "vulnerability":
        value = value.upper()
        if not re.fullmatch("CVE-[0-9]{4}-[0-9]{4,}", value):
            raise ModuleError("A CVE identifier is required.")
    return value


def _object(event, attribute, name):
    obj = MISPObject(name)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)
    return obj


def _annotation(event, attribute, title, data):
    obj = _object(event, attribute, "annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True), to_ids=False, disable_correlation=True)
    return obj


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        attribute = request["attribute"]
        UUID(attribute["uuid"])
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        value = _normalise(attribute["type"], attribute["value"])
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be an object.")
        for key in REQUIRED:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        limit = _integer(config, "max_results", 25)
        event = MISPEvent()
        event.add_attribute(**attribute)
        _expand(event, attribute, value, config, limit)
        result = json.loads(event.to_json())
        return {"results": {key: result.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        PyMISPError,
    ):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "DNSTwist Domain Enrichment",
    "description": (
        "Generate domain permutations locally with optional DNS resolution. Install dnstwist in the module server"
        " Python environment. resolve defaults to false and performs no DNS checks. Set resolve=true to return"
        " DNS-resolving candidates with available A, AAAA, NS and MX observations. timeout defaults to 30 seconds"
        " (1–120); threads defaults to 4 (1–16). An isolated subprocess prevents changes to the module server argument"
        " list and bounds runtime. Generated candidates and resolving domains are investigation leads, not"
        " maliciousness assertions. Each result preserves its mutation algorithm."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp", "dnstwist"],
    "features": (
        "Generate domain permutations locally with optional DNS resolution. Install dnstwist in the module server"
        " Python environment. resolve defaults to false and performs no DNS checks. Set resolve=true to return"
        " DNS-resolving candidates with available A, AAAA, NS and MX observations. timeout defaults to 30 seconds"
        " (1–120); threads defaults to 4 (1–16). An isolated subprocess prevents changes to the module server argument"
        " list and bounds runtime. Generated candidates and resolving domains are investigation leads, not"
        " maliciousness assertions. Each result preserves its mutation algorithm."
    ),
    "references": ["https://github.com/elceef/dnstwist"],
    "input": "domain, hostname",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleconfig = ["resolve", "timeout", "threads", "max_results"]
REQUIRED = []


def _expand(event, attribute, value, config, limit):
    import subprocess
    import sys
    import tempfile

    timeout = _integer(config, "timeout", 30, 120)
    threads = _integer(config, "threads", 4, 16)
    resolve = _enabled(config, "resolve")
    if resolve:
        command = [
            sys.executable,
            "-m",
            "dnstwist",
            "--format",
            "json",
            "--threads",
            str(threads),
            "--registered",
            value,
        ]
    else:
        program = (
            "import dnstwist,json,sys; f=dnstwist.Fuzzer(sys.argv[1]); f.generate(); print(json.dumps([dict(row) for"
            " row in f.permutations()]))"
        )
        command = [sys.executable, "-c", program, value]
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise ModuleError("DNSTwist exceeded timeout; narrow the domain or increase timeout.") from None
        if completed.returncode:
            raise ModuleError("DNSTwist failed; install the dnstwist package in the module server environment.")
        output.seek(0, 2)
        if output.tell() > 16 * 1024 * 1024:
            raise ModuleError("DNSTwist output exceeded the size limit.")
        output.seek(0)
        raw = output.read().decode("utf-8")
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ModuleError("DNSTwist returned invalid results.")
    rows = [row for row in rows if row.get("domain") != value]
    for row in rows[:limit]:
        candidate = _normalise("domain", row["domain"])
        obj = _object(event, attribute, "domain-ip")
        obj.add_attribute("domain", value=candidate, to_ids=False)
        obj.add_attribute("text", value=json.dumps({"fuzzer": row.get("fuzzer"), "dns_checked": resolve}), to_ids=False)
        for key in ("dns_a", "dns_aaaa"):
            for address in row.get(key, [])[:limit]:
                try:
                    parsed_address = str(ipaddress.ip_address(address))
                except ValueError:
                    _annotation(
                        event,
                        attribute,
                        "DNSTwist DNS lookup failure",
                        {"domain": candidate, "record": key, "status": str(address)},
                    )
                    continue
                obj.add_attribute("ip", value=parsed_address, to_ids=False)
        for key in ("dns_ns", "dns_mx"):
            if row.get(key):
                _annotation(event, attribute, "DNSTwist DNS observation", {"domain": candidate, key: row[key]})
    if len(rows) > limit:
        _annotation(event, attribute, "Result limit", {"truncated": True, "total": len(rows), "max_results": limit})
