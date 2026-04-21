import hashlib
import json
import socket


misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Mihai Catalin Teodosiu",
    "description": "Grab SSH server key fingerprint from an IP address for verification or MitM detection.",
    "module-type": ["expansion", "hover"],
    "name": "SSH Fingerprint",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes an IP address attribute as input, connects to port 22,"
        " performs the SSH protocol version exchange and key exchange init to extract"
        " the server host key algorithms and SSH banner. Useful for detecting MitM"
        " attacks or verifying server identity changes."
    ),
    "references": ["https://tools.ietf.org/html/rfc4253"],
    "input": "An IP address attribute (ip-src or ip-dst).",
    "output": "Text containing SSH banner and key exchange information.",
}
moduleconfig = ["port", "timeout"]


def _grab_ssh_banner(ip, port=22, timeout=5):
    result = {
        "banner": None,
        "kex_algorithms": None,
        "host_key_algorithms": None,
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
            if payload and payload[0:1] == b"\x14":
                payload = payload[16:]
                if payload and payload[0:1] == b"\x14":
                    pass

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

    ip = request.get("ip-src") or request.get("ip-dst")
    if not ip:
        misperrors["error"] = "An IP address attribute is required."
        return misperrors

    config = request.get("config", {})
    port = int(config.get("port") or 22)
    timeout = float(config.get("timeout") or 5)

    result = _grab_ssh_banner(ip, port, timeout)

    lines = [f"=== SSH Fingerprint: {ip}:{port} ===", ""]

    if result["error"]:
        lines.append(f"Error: {result['error']}")
        return {"results": [{"types": ["text"], "values": "\n".join(lines)}]}

    if result["banner"]:
        lines.append(f"Banner: {result['banner']}")

    if result.get("host_key_algorithms"):
        lines.append(f"\nHost Key Algorithms: {result['host_key_algorithms']}")

    if result.get("kex_algorithms"):
        lines.append(f"KEX Algorithms: {result['kex_algorithms']}")

    if result.get("kex_hash"):
        lines.append(f"\nKEX Init Hash (SHA256): {result['kex_hash']}")
        lines.append("  (Compare this hash over time to detect server key changes)")

    return {"results": [{"types": ["text"], "values": "\n".join(lines)}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
