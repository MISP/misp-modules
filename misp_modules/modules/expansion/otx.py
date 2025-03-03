import json
import re

import requests

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst",
        "md5",
        "sha1",
        "sha256",
        "sha512",
    ],
    "output": [
        "domain",
        "ip-src",
        "ip-dst",
        "text",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "email",
    ],
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "chrisdoman",
    "description": "Module to get information from AlienVault OTX.",
    "module-type": ["expansion"],
    "name": "AlienVault OTX Lookup",
    "logo": "otx.png",
    "requirements": ["An access to the OTX API (apikey)"],
    "features": (
        "This module takes a MISP attribute as input to query the OTX Alienvault API. The API returns then the result"
        " of the query with some types we map into compatible types we add as MISP attributes."
    ),
    "references": ["https://www.alienvault.com/open-threat-exchange"],
    "input": (
        "A MISP attribute included in the following list:\n- hostname\n- domain\n- ip-src\n- ip-dst\n- md5\n- sha1\n-"
        " sha256\n- sha512"
    ),
    "output": (
        "MISP attributes mapped from the result of the query on OTX, included in the following list:\n- domain\n-"
        " ip-src\n- ip-dst\n- text\n- md5\n- sha1\n- sha256\n- sha512\n- email"
    ),
}

# We're not actually using the API key yet
moduleconfig = ["apikey"]


# Avoid adding windows update to enrichment etc.
def isBlacklisted(value):
    blacklist = [
        "0.0.0.0",
        "8.8.8.8",
        "255.255.255.255",
        "192.168.56.",
        "time.windows.com",
    ]

    for b in blacklist:
        if value in b:
            return False

    return True


def valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))


def findAll(data, keys):
    a = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key == keys:
                a.append(value)
            else:
                if isinstance(value, (dict, list)):
                    a.extend(findAll(value, keys))
    if isinstance(data, list):
        for i in data:
            a.extend(findAll(i, keys))
    return a


def valid_email(email):
    return bool(
        re.search(
            r"[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
            email,
        )
    )


def handler(q=False):
    if q is False:
        return False

    q = json.loads(q)

    key = q["config"]["apikey"]

    r = {"results": []}

    if "ip-src" in q:
        r["results"] += getIP(q["ip-src"], key)
    if "ip-dst" in q:
        r["results"] += getIP(q["ip-dst"], key)
    if "domain" in q:
        r["results"] += getDomain(q["domain"], key)
    if "hostname" in q:
        r["results"] += getDomain(q["hostname"], key)
    if "md5" in q:
        r["results"] += getHash(q["md5"], key)
    if "sha1" in q:
        r["results"] += getHash(q["sha1"], key)
    if "sha256" in q:
        r["results"] += getHash(q["sha256"], key)
    if "sha512" in q:
        r["results"] += getHash(q["sha512"], key)

    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
    return r


def getHash(_hash, key):

    ret = []
    req = json.loads(requests.get("https://otx.alienvault.com/otxapi/indicator/file/analysis/" + _hash).text)

    for ip in findAll(req, "dst"):
        if not isBlacklisted(ip) and valid_ip(ip):
            ret.append({"types": ["ip-dst", "ip-src"], "values": [ip]})

    for domain in findAll(req, "hostname"):
        if "." in domain and not isBlacklisted(domain):
            ret.append({"types": ["hostname"], "values": [domain]})

    return ret


def getIP(ip, key):
    ret = []
    req = json.loads(requests.get("https://otx.alienvault.com/otxapi/indicator/ip/malware/" + ip + "?limit=1000").text)

    for _hash in findAll(req, "hash"):
        ret.append({"types": ["sha256"], "values": [_hash]})

    req = json.loads(requests.get("https://otx.alienvault.com/otxapi/indicator/ip/passive_dns/" + ip).text)

    for hostname in findAll(req, "hostname"):
        if not isBlacklisted(hostname):
            ret.append({"types": ["hostname"], "values": [hostname]})

    return ret


def getDomain(domain, key):

    ret = []

    req = json.loads(
        requests.get("https://otx.alienvault.com/otxapi/indicator/domain/malware/" + domain + "?limit=1000").text
    )

    for _hash in findAll(req, "hash"):
        ret.append({"types": ["sha256"], "values": [_hash]})

    req = json.loads(requests.get("https://otx.alienvault.com/otxapi/indicator/domain/whois/" + domain).text)

    for _domain in findAll(req, "domain"):
        ret.append({"types": ["hostname"], "values": [_domain]})

    for email in findAll(req, "value"):
        if valid_email(email):
            ret.append({"types": ["email"], "values": [email]})

    for _domain in findAll(req, "hostname"):
        if "." in _domain and not isBlacklisted(_domain):
            ret.append({"types": ["hostname"], "values": [_domain]})

    req = json.loads(requests.get("https://otx.alienvault.com/otxapi/indicator/hostname/passive_dns/" + domain).text)
    for ip in findAll(req, "address"):
        if valid_ip(ip):
            ret.append({"types": ["ip-dst"], "values": [ip]})

    return ret


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
