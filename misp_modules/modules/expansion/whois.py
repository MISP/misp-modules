# -*- coding: utf-8 -*-

import json
import socket

misperrors = {"error": "Error"}
# freetext, not misp_standard, and deliberately so: MISP runs its freetext
# importer over what this module returns, and a registration record is dense
# with what that importer is built to find - registrant emails, nameservers,
# addresses, related domains. Returning a whois object carrying the record as
# one text attribute would look tidier and extract nothing.
mispattributes = {"input": ["domain", "ip-src", "ip-dst"], "output": ["freetext"]}
moduleinfo = {
    "version": "0.2",
    "author": "Raphaël Vinot",
    "description": (
        "Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd). It returns the registration"
        " record as raw text; the rdap module answers the same question as a structured whois object, over an"
        " unauthenticated protocol and without a local server, and is the better choice wherever RDAP covers the"
        " registry."
    ),
    "module-type": ["expansion"],
    "name": "Whois Lookup",
    "logo": "",
    "requirements": ["uwhois: A whois python library"],
    "features": (
        "This module takes a domain or IP address attribute as input and queries a 'Univseral Whois proxy server' to"
        " get the correct details of the Whois query on the input value (check the references for more details about"
        " this whois server)."
    ),
    "references": ["https://github.com/Lookyloo/uwhoisd", "https://about.rdap.org/"],
    "input": "A domain or IP address attribute.",
    "output": "Text describing the result of a whois request for the input value. See the rdap module for objects.",
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

    config = request.get("config") or {}
    server = config.get("server")
    port = config.get("port")
    # Both are needed: the old check only fired when both were absent, and then
    # read config["server"] unguarded.
    if not server or not port:
        misperrors["error"] = "Whois local instance address is missing"
        return misperrors

    # This used to run only when the request carried an event_id, and fell off
    # the end returning None otherwise.
    try:
        return handle_expansion(server, int(port), toquery)
    except (OSError, ValueError) as e:
        misperrors["error"] = f"Not able to reach the uwhois instance at {server}:{port}: {e}"
        return misperrors


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
