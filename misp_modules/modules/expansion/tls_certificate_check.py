import json
import socket
import ssl
from datetime import datetime, timezone


misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Mihai Catalin Teodosiu",
    "description": "Extract TLS certificate details from a domain: issuer, validity, SANs, chain info.",
    "module-type": ["expansion", "hover"],
    "name": "TLS Certificate Check",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes a domain or hostname attribute as input, connects to port 443,"
        " performs a TLS handshake and extracts certificate details including issuer,"
        " subject, validity period, Subject Alternative Names, serial number, and"
        " protocol version. No external API required — pure Python ssl module."
    ),
    "references": ["https://tools.ietf.org/html/rfc5246"],
    "input": "A domain or hostname attribute.",
    "output": "Text containing TLS certificate details and assessment.",
}
moduleconfig = ["port", "timeout"]


def _get_cert_info(domain, port=443, timeout=5):
    result = {
        "subject": None,
        "issuer": None,
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
                result["issuer"] = (
                    f"{issuer.get('organizationName', 'N/A')}"
                    f" ({issuer.get('commonName', 'N/A')})"
                )

                result["serial"] = str(cert.get("serialNumber", "N/A"))
                result["not_before"] = cert.get("notBefore", "N/A")
                result["not_after"] = cert.get("notAfter", "N/A")

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

    domain = request.get("domain") or request.get("hostname")
    if not domain:
        misperrors["error"] = "A domain or hostname attribute is required."
        return misperrors

    config = request.get("config", {})
    port = int(config.get("port") or 443)
    timeout = float(config.get("timeout") or 5)

    result = _get_cert_info(domain, port, timeout)

    lines = [f"=== TLS Certificate: {domain}:{port} ===", ""]

    if result["error"]:
        lines.append(f"Error: {result['error']}")
        return {"results": [{"types": ["text"], "values": "\n".join(lines)}]}

    lines.append(f"Subject: {result['subject']}")
    lines.append(f"Issuer: {result['issuer']}")
    lines.append(f"Serial: {result['serial']}")
    lines.append(f"Protocol: {result['protocol']}")
    lines.append(f"\nValid From: {result['not_before']}")
    lines.append(f"Valid Until: {result['not_after']}")

    days_left = _days_until_expiry(result["not_after"])
    if days_left is not None:
        if days_left < 0:
            lines.append(f"STATUS: EXPIRED ({abs(days_left)} days ago)")
        elif days_left < 30:
            lines.append(f"STATUS: EXPIRING SOON ({days_left} days left)")
        else:
            lines.append(f"STATUS: VALID ({days_left} days remaining)")

    if result["sans"]:
        lines.append(f"\nSubject Alternative Names ({len(result['sans'])}):")
        for san in result["sans"][:20]:
            lines.append(f"  - {san}")
        if len(result["sans"]) > 20:
            lines.append(f"  ... and {len(result['sans']) - 20} more")

    return {"results": [{"types": ["text"], "values": "\n".join(lines)}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
