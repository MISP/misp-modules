import json

from dns.name import LabelTooLong
from dns.resolver import NXDOMAIN, Resolver

resolver = Resolver()
resolver.timeout = 1
resolver.lifetime = 1


misperrors = {"error": "Error"}
mispattributes = {"input": ["btc"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Christian Studer",
    "description": (
        "An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused."
    ),
    "module-type": ["hover"],
    "name": "BTC Scam Check",
    "logo": "bitcoin.png",
    "requirements": ["dnspython3: dns python library"],
    "features": (
        "The module queries a dns blacklist directly with the bitcoin address and get a response if the address has"
        " been abused."
    ),
    "references": ["https://btcblack.it/"],
    "input": "btc address attribute.",
    "output": "Text to indicate if the BTC address has been abused.",
}
moduleconfig = []

url = "bl.btcblack.it"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    btc = request["btc"]
    query = f"{btc}.{url}"
    try:
        result = " - ".join([str(r) for r in resolver.resolve(query, "TXT")])[1:-1]
    except NXDOMAIN:
        result = f"{btc} is not known as a scam address."
    except LabelTooLong:
        result = f"{btc} is probably not a valid BTC address."
    return {"results": [{"types": mispattributes["output"], "values": result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
