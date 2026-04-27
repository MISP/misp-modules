import json
import socket
import ssl
from datetime import datetime, timezone

from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Mihai Saveanu",
    "description": "Extract TLS certificate details from a domain and return as x509 MISP object.",
    "module-type": ["expansion", "hover"],
    "name": "TLS Certificate Check",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes a domain or hostname attribute as input, connects to port 443,"
        " performs a TLS handshake and extracts certificate details. Returns a structured"
        " x509 MISP object with subject, issuer, validity, SANs, serial number, and"
        " protocol version. No external API required."
    ),
    "references": ["https://tools.ietf.org/html/rfc5246"],
    "input": "A domain or hostname attribute.",
    "output": "x509 MISP object with certificate details.",
}
moduleconfig = ["port", "timeout"]


def _get_cert_info(domain, port=443, timeout=5):
    result = {
        "subject": None,
        "issuer": None,
        "issuer_org": None,
        "issuer_cn": None,
        "serial": None,
        "not_before": None,
        "not_after": None,
        "sans": [],
        "protocol": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result["protocol"] = tls.version()

                subj = dict(x[0] for x in cert.get("subject", ()))
                result["subject"] = subj.get("commonName", "N/A")

                issuer = dict(x[0] for x in cert.get("issuer", ()))
                result["issuer_org"] = issuer.get("organizationName", "")
                result["issuer_cn"] = issuer.get("commonName", "")
                result["issuer"] = (
                    f"{result['issuer_org']} ({result['issuer_cn']})"
                    if result["issuer_org"]
                    else result["issuer_cn"]
                )

                result["serial"] = str(cert.get("serialNumber", "N/A"))
                result["not_before"] = cert.get("notBefore", "")
                result["not_after"] = cert.get("notAfter", "")

                for entry_type, entry_value in cert.get("subjectAltName", ()):
                    if entry_type == "DNS":
                        result["sans"].append(entry_value)

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port closed)"
    except Exception as e:
        result["error"] = str(e)

    return result


def _parse_datetime(date_str):
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    except Exception:
        return None


def _days_until_expiry(not_after_str):
    try:
        expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except Exception:
        return None


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if not request.get("attribute") or not request["attribute"].get("type"):
        return {"error": "Missing or invalid attribute."}

    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": f"Unsupported attribute type: {attribute['type']}"}

    domain = attribute["value"]
    config = request.get("config", {})
    port = int(config.get("port") or 443)
    timeout = float(config.get("timeout") or 5)

    result = _get_cert_info(domain, port, timeout)

    event = MISPEvent()
    initial_attribute = MISPAttribute()
    initial_attribute.from_dict(**attribute)
    event.add_attribute(**initial_attribute)

    if result["error"]:
        event.add_attribute(
            "text",
            f"TLS error for {domain}: {result['error']}",
            comment="TLS Certificate Check - error",
        )
        ev = json.loads(event.to_json())
        results = {key: ev[key] for key in ("Attribute", "Object") if key in ev and ev[key]}
        return {"results": results}

    x509 = MISPObject("x509")

    x509.add_attribute("serial-number", **{"type": "text", "value": result["serial"]})
    x509.add_attribute("issuer", **{"type": "text", "value": result["issuer"], "disable_correlation": True})
    x509.add_attribute("subject", **{"type": "text", "value": result["subject"]})

    if result["protocol"]:
        x509.add_attribute("version", **{"type": "text", "value": result["protocol"], "disable_correlation": True})

    not_before_iso = _parse_datetime(result["not_before"])
    not_after_iso = _parse_datetime(result["not_after"])

    if not_before_iso:
        x509.add_attribute("validity-not-before", **{"type": "datetime", "value": not_before_iso, "disable_correlation": True})
    if not_after_iso:
        x509.add_attribute("validity-not-after", **{"type": "datetime", "value": not_after_iso, "disable_correlation": True})

    for san in result["sans"][:50]:
        x509.add_attribute("dns_names", **{"type": "hostname", "value": san})

    days_left = _days_until_expiry(result["not_after"])
    if days_left is not None:
        if days_left < 0:
            status = f"EXPIRED ({abs(days_left)} days ago)"
        elif days_left < 30:
            status = f"EXPIRING SOON ({days_left} days left)"
        else:
            status = f"VALID ({days_left} days remaining)"
        x509.add_attribute("text", **{"type": "text", "value": status, "disable_correlation": True})

    x509.add_reference(initial_attribute.uuid, "related-to")
    event.add_object(**x509)

    ev = json.loads(event.to_json())
    results = {key: ev[key] for key in ("Attribute", "Object") if key in ev and ev[key]}
    return {"results": results}


def introspection():
    return mispattributes


def version():
    return moduleinfo
