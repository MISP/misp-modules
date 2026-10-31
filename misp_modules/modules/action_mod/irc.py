"""Send workflow messages to an IRC channel using a short-lived connection."""

import json
import re
import socket
import ssl
from time import monotonic
from uuid import uuid4

from jinja2 import TemplateError

from ._utils import utils

misperrors = {"error": "Error"}

moduleconfig = {
    "params": {
        "irc_server": {"type": "string", "description": "IRC server hostname", "value": "irc.example.org"},
        "irc_port": {"type": "string", "description": "IRC server port", "value": "6697"},
        "use_tls": {
            "type": "string",
            "description": "true for verified TLS, false for a plaintext connection",
            "value": "true",
        },
        "nickname": {"type": "string", "description": "Nickname for this connection", "value": "misp"},
        "channel": {"type": "string", "description": "IRC channel to join", "value": "#misp"},
        "server_password": {"type": "string", "description": "Optional server PASS password", "value": ""},
        "channel_key": {"type": "string", "description": "Optional channel JOIN key", "value": ""},
        "message_template": {
            "type": "large_string",
            "description": "Jinja2 message template; leave empty to send the workflow data as JSON",
            "value": "MISP event: {{ Event.info }}",
            "jinja_supported": True,
        },
    },
    "blocking": False,
    "support_filters": True,
    "expect_misp_core_format": False,
}

returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": "Send a message to an IRC channel.",
    "module-type": ["action"],
    "name": "IRC",
    "logo": "",
    "requirements": [],
    "features": (
        "Renders Jinja2 templates using matchingData when present, otherwise data, with a JSON fallback."
        " Supports verified TLS, server passwords and channel keys. Splits multiline and long UTF-8 messages"
        " into IRC PRIVMSG lines. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/irc.md)."
    ),
    "references": ["https://modern.ircdocs.horse/"],
    "input": "Workflow data or matchingData, and an optional Jinja2 message template.",
    "output": "Boolean success after server processing; IRC provides no recipient delivery receipt.",
}


def _casefold(value):
    # RFC 1459 channel and nickname casemapping.
    return value.lower().translate(str.maketrans("[]\\^", "{}|~"))


def _message_lines(message, channel):
    if any(ord(char) < 32 and char not in "\r\n\t" or ord(char) == 127 for char in message):
        raise ValueError("IRC message contains control characters")
    prefix = f"PRIVMSG {channel} :"
    budget = 510 - len(prefix.encode("utf-8"))
    if budget < 4:
        raise ValueError("IRC channel is too long")
    lines = []
    for line in message.replace("\t", " ").splitlines():
        encoded = line.encode("utf-8")
        while encoded:
            chunk = encoded[:budget].decode("utf-8", errors="ignore")
            lines.append(prefix + chunk)
            encoded = encoded[len(chunk.encode("utf-8")) :]
    if not lines:
        raise ValueError("Empty IRC message")
    return lines


def _send_message(sock, params, lines, deadline):
    def remaining():
        timeout = deadline - monotonic()
        if timeout <= 0:
            raise TimeoutError("IRC operation timed out")
        return timeout

    def send(line):
        encoded = (line + "\r\n").encode("utf-8")
        if len(encoded) > 512 or "\r" in line or "\n" in line:
            raise ValueError("Invalid IRC command")
        sock.settimeout(remaining())
        sock.sendall(encoded)

    def receive(stream):
        while True:
            sock.settimeout(remaining())
            raw = stream.readline(8193)
            if not raw or len(raw) > 8192 or not raw.endswith(b"\n"):
                raise OSError("IRC connection closed or invalid response")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith("@"):
                line = line.split(" ", 1)[1]
            prefix = ""
            if line.startswith(":"):
                prefix, line = line[1:].split(" ", 1)
            head, separator, tail = line.partition(" :")
            parts = head.split()
            if separator:
                parts.append(tail)
            if not parts:
                continue
            command, args = parts[0].upper(), parts[1:]
            if command == "PING" and args:
                send(f"PONG :{args[-1]}")
                continue
            if command == "ERROR" or (command.isdigit() and 400 <= int(command) <= 599 and command != "422"):
                raise OSError("IRC server rejected the operation")
            return prefix, command, args

    with sock.makefile("rb") as stream:
        if params.get("server_password"):
            send(f"PASS :{params['server_password']}")
        send(f"NICK {params['nickname']}")
        send(f"USER {params['nickname']} 0 * :MISP workflow")
        while True:
            _, command, args = receive(stream)
            if command == "001" and args:
                nickname = args[0]
                break

        channel = params["channel"]
        key = params.get("channel_key", "")
        send(f"JOIN {channel}" + (f" {key}" if key else ""))
        while True:
            prefix, command, args = receive(stream)
            if (
                command == "JOIN"
                and args
                and _casefold(prefix.split("!", 1)[0]) == _casefold(nickname)
                and _casefold(args[0]) == _casefold(channel)
            ):
                break

        for line in lines:
            send(line)
        # A PONG after the messages lets us observe errors for preceding commands.
        token = uuid4().hex
        send(f"PING :{token}")
        while True:
            _, command, args = receive(stream)
            if command == "PONG" and args and args[-1] == token:
                break
        send("QUIT :MISP workflow complete")


def create_post(request):
    params = request["params"]
    for name in ("irc_server", "nickname", "channel", "channel_key"):
        value = params.get(name, "")
        if not isinstance(value, str) or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid IRC configuration")
    if not params["irc_server"] or not re.fullmatch(
        r"[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]*", params["nickname"]
    ):
        raise ValueError("Invalid IRC server or nickname")
    if not re.fullmatch(r"[#&][^,:\s\x00-\x1f\x7f]+", params["channel"]):
        raise ValueError("Invalid IRC channel")
    if any(char in params.get("channel_key", "") for char in ",:"):
        raise ValueError("Invalid IRC channel key")
    password = params.get("server_password", "")
    if not isinstance(password, str) or any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise ValueError("Invalid IRC server password")
    commands = [
        f"NICK {params['nickname']}",
        f"USER {params['nickname']} 0 * :MISP workflow",
        f"JOIN {params['channel']} {params.get('channel_key', '')}",
        f"PASS :{password}",
    ]
    if any(len(command.encode("utf-8")) > 510 for command in commands):
        raise ValueError("IRC configuration exceeds command length limits")
    port = params.get("irc_port", "6697")
    if isinstance(port, bool) or not re.fullmatch(r"[0-9]{1,5}", str(port)) or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid IRC port")
    tls = params.get("use_tls", "true")
    if isinstance(tls, str):
        tls = {"true": True, "false": False}.get(tls.lower())
    if not isinstance(tls, bool):
        raise ValueError("Invalid IRC TLS setting")

    data = request["matchingData"] if "matchingData" in request else request["data"]
    template = params.get("message_template", "")
    if not isinstance(template, str):
        raise ValueError("Invalid message template")
    message = utils.renderTemplate(data, template) if template else "```\n{}\n```".format(json.dumps(data))
    lines = _message_lines(message, params["channel"])
    deadline = monotonic() + 30
    with socket.create_connection((params["irc_server"], int(port)), timeout=30) as sock:
        if tls:
            timeout = deadline - monotonic()
            if timeout <= 0:
                raise TimeoutError("IRC operation timed out")
            sock.settimeout(timeout)
            with ssl.create_default_context().wrap_socket(sock, server_hostname=params["irc_server"]) as secured:
                _send_message(secured, params, lines, deadline)
        else:
            _send_message(sock, params, lines, deadline)
    return True


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("params"), dict):
            raise ValueError("Invalid request")
        create_post(request)
    except OSError:
        return {
            "data": False,
            "error": "IRC connection or send failed; check TLS, nickname, credentials and channel access.",
        }
    except (KeyError, IndexError, TypeError, ValueError, TemplateError):
        return {"data": False, "error": "Invalid IRC configuration, workflow data, template or server response."}
    return {"data": True}


def introspection():
    return {"config": moduleconfig}


def version():
    return {**moduleinfo, "config": moduleconfig}
