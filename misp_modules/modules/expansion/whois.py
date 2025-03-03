# -*- coding: utf-8 -*-

import json
import socket

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "ip-src", "ip-dst"], "output": ["freetext"]}
moduleinfo = {
    "version": "0.1",
    "author": "Raphaël Vinot",
    "description": "Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).",
    "module-type": ["expansion"],
    "name": "Whois Lookup",
    "logo": "",
    "requirements": ["uwhois: A whois python library"],
    "features": (
        "This module takes a domain or IP address attribute as input and queries a 'Univseral Whois proxy server' to"
        " get the correct details of the Whois query on the input value (check the references for more details about"
        " this whois server)."
    ),
    "references": ["https://github.com/Lookyloo/uwhoisd"],
    "input": "A domain or IP address attribute.",
    "output": "Text describing the result of a whois request for the input value.",
}

moduleconfig = ["server", "port"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("domain"):
        toquery = request["domain"]
    elif request.get("ip-src"):
        toquery = request["ip-src"]
    elif request.get("ip-dst"):
        toquery = request["ip-dst"]
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if not request.get("config") or (not request["config"].get("server") and not request["config"].get("port")):
        misperrors["error"] = "Whois local instance address is missing"
        return misperrors

    if "event_id" in request:
        return handle_expansion(request["config"]["server"], int(request["config"]["port"]), toquery)


def handle_expansion(server, port, query):
    bytes_whois = b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server, port))
        sock.sendall(f"{query}\n".encode())
        while True:
            data = sock.recv(2048)
            if not data:
                break
            bytes_whois += data
    return {"results": [{"types": mispattributes["output"], "values": bytes_whois.decode()}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
