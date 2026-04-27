import hashlib
import json
import socket

from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Mihai Saveanu",
    "description": "Grab SSH server fingerprint from an IP and return as passive-ssh MISP object.",
    "module-type": ["expansion", "hover"],
    "name": "SSH Fingerprint",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes an IP address attribute as input, connects to port 22,"
        " performs the SSH protocol version exchange and key exchange init to extract"
        " the server host key algorithms and SSH banner. Returns a structured passive-ssh"
        " MISP object. Useful for detecting MitM attacks or verifying server identity."
    ),
    "references": ["https://tools.ietf.org/html/rfc4253"],
    "input": "An IP address attribute (ip-src or ip-dst).",
    "output": "passive-ssh MISP object with banner and fingerprint.",
}
moduleconfig = ["port", "timeout"]


def _grab_ssh_banner(ip, port=22, timeout=5):
    result = {
        "banner": None,
        "kex_algorithms": None,
        "host_key_algorithms": None,
        "kex_hash": None,
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        result["banner"] = banner

        sock.sendall(b"SSH-2.0-MISP_Fingerprint_Module\r\n")

        kex_data = sock.recv(4096)
        if len(kex_data) > 21:
            payload = kex_data[5:]

            try:
                msg_code = payload[0]
                if msg_code == 20:
                    offset = 17
                    if offset < len(payload):
                        kex_len = int.from_bytes(
                            payload[offset : offset + 4], "big"
                        )
                        offset += 4
                        if offset + kex_len <= len(payload):
                            kex_str = payload[offset : offset + kex_len].decode(
                                "utf-8", errors="replace"
                            )
                            result["kex_algorithms"] = kex_str
                            offset += kex_len

                        hk_len = int.from_bytes(
                            payload[offset : offset + 4], "big"
                        )
                        offset += 4
                        if offset + hk_len <= len(payload):
                            hk_str = payload[offset : offset + hk_len].decode(
                                "utf-8", errors="replace"
                            )
                            result["host_key_algorithms"] = hk_str
            except (IndexError, ValueError):
                pass

            raw_hash = hashlib.sha256(kex_data).hexdigest()
            result["kex_hash"] = raw_hash

        sock.close()
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port closed)"
    except Exception as e:
        result["error"] = str(e)

    return result


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if not request.get("attribute") or not request["attribute"].get("type"):
        return {"error": "Missing or invalid attribute."}

    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": f"Unsupported attribute type: {attribute['type']}"}

    ip = attribute["value"]
    config = request.get("config", {})
    port = int(config.get("port") or 22)
    timeout = float(config.get("timeout") or 5)

    result = _grab_ssh_banner(ip, port, timeout)

    event = MISPEvent()
    initial_attribute = MISPAttribute()
    initial_attribute.from_dict(**attribute)
    event.add_attribute(**initial_attribute)

    if result["error"]:
        event.add_attribute(
            "text",
            f"SSH error for {ip}: {result['error']}",
            comment="SSH Fingerprint - error",
        )
        ev = json.loads(event.to_json())
        results = {key: ev[key] for key in ("Attribute", "Object") if key in ev and ev[key]}
        return {"results": results}

    ssh = MISPObject("passive-ssh")

    ssh.add_attribute("host", **{"type": "ip-dst", "value": ip})
    ssh.add_attribute("port", **{"type": "port", "value": port})

    if result["banner"]:
        ssh.add_attribute("banner", **{"type": "text", "value": result["banner"]})

    if result["kex_hash"]:
        ssh.add_attribute(
            "fingerprint",
            **{"type": "ssh-fingerprint", "value": result["kex_hash"]},
        )

    ssh.add_reference(initial_attribute.uuid, "related-to")
    event.add_object(**ssh)

    ev = json.loads(event.to_json())
    results = {key: ev[key] for key in ("Attribute", "Object") if key in ev and ev[key]}
    return {"results": results}


def introspection():
    return mispattributes


def version():
    return moduleinfo
