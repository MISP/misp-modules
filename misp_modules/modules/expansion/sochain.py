"""Look up a Bitcoin, Litecoin, Dogecoin or Zcash address on SoChain."""

import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["btc", "coin-address"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "Atif Nazir",
    "description": (
        "Get the balance, activity, counterparties and address poisoning findings of a BTC, LTC, DOGE or ZEC address"
        " from SoChain."
    ),
    "module-type": ["expansion", "hover"],
    "name": "SoChain",
    "logo": "",
    "requirements": ["requests", "PyMISP"],
    "features": (
        "Query the SoChain API v3 for a btc attribute or a coin-address object. A btc attribute is looked up"
        " on Bitcoin. A coin-address object is looked up on the network named by its symbol (BTC, LTC, DOGE or"
        " ZEC); without a symbol, the network is the first of Bitcoin, Litecoin, Dogecoin and Zcash on which"
        " SoChain says the address is valid.\n\n"
        "The result is a coin-address object with the balance, total received and sent, the number of"
        " transactions and the first and last activity, referencing the input. Recent counterparties are"
        " returned as coin-address objects linked with `paid` references (5 on hover, 50 when the magnifying"
        " glass is clicked), whose comments give the amount, transaction and block. When look-alike addresses"
        " sent the address dust to poison its history, each one is returned as a coin-address object that"
        " `impersonates` the address it copies.\n\n"
        "No API key is needed for up to 2,500 lookups a day per IP. With a key from"
        " https://sochain.com/dashboard, lookups count against that account's plan."
    ),
    "references": ["https://sochain.com/docs", "https://sochain.com/api/v3/openapi.json"],
    "input": "A btc attribute, or a coin-address object with a BTC, LTC, DOGE or ZEC address.",
    "output": "coin-address objects: the address, its recent counterparties and any look-alike addresses.",
}
moduleconfig = ["apikey"]

API_URL = "https://sochain.com/api/v3"
TIMEOUT = 15
NETWORKS = ("BTC", "LTC", "DOGE", "ZEC")
# Tried first when the address starts like this; every network is still tried in the end.
PREFIXES = {
    "BTC": ("bc1", "1", "3"),
    "LTC": ("ltc1", "L", "M", "3"),
    "DOGE": ("D", "A", "9"),
    "ZEC": ("t1", "t3"),
}
ADDRESS = re.compile(r"^[A-Za-z0-9]{1,1000}$")


class SoChainError(Exception):
    pass


class SoChain:
    def __init__(self, apikey=None):
        self.headers = {"Accept": "application/json"}
        if apikey:
            self.headers["API-KEY"] = apikey

    def get(self, endpoint, network, address, **params):
        """The data of an answer, or None when SoChain answers 404."""
        try:
            response = requests.get(
                f"{API_URL}/{endpoint}/{network}/{address}", headers=self.headers, params=params, timeout=TIMEOUT
            )
        except requests.RequestException as e:
            raise SoChainError(f"Not able to reach SoChain: {e}")
        if response.status_code == 404:
            return None
        if response.status_code == 401:
            raise SoChainError("SoChain refused the API key. Check it at https://sochain.com/dashboard.")
        if response.status_code == 429:
            raise SoChainError(
                "SoChain's lookup limit is reached. An API key from https://sochain.com/dashboard raises it."
            )
        try:
            payload = response.json()
        except ValueError:
            raise SoChainError(f"SoChain answered with HTTP {response.status_code} and no JSON.")
        if response.status_code != 200 or payload.get("status") != "success":
            message = (payload.get("data") or {}).get("error_message") or f"HTTP {response.status_code}"
            raise SoChainError(f"SoChain: {message}")
        return payload["data"]

    def detect_network(self, address):
        hinted = [n for n in NETWORKS if address.startswith(PREFIXES[n])]
        for network in hinted + [n for n in NETWORKS if n not in hinted]:
            data = self.get("is_valid_address", network, address)
            if data and data.get("is_valid"):
                return network
        return None


def _coin(amount):
    try:
        return Decimal(amount)
    except (InvalidOperation, TypeError):
        raise SoChainError(f"SoChain returned an amount that is not a number: {amount!r}")


def _timestamp(block):
    if block and block.get("time"):
        return datetime.fromtimestamp(int(block["time"]), tz=timezone.utc)
    return None


def _address_object(address, network):
    misp_object = MISPObject("coin-address")
    # The address relation is a btc attribute; other coins go in address-crypto.
    misp_object.add_attribute("address" if network == "BTC" else "address-crypto", address)
    misp_object.add_attribute("symbol", network)
    return misp_object


def _wallet(address, network, summary):
    wallet = _address_object(address, network)
    balance = _coin(summary["confirmed_balance"])
    received = _coin(summary["confirmed_received"])
    wallet.add_attribute("current-balance", format(balance, "f"))
    wallet.add_attribute("total-received", format(received, "f"))
    wallet.add_attribute("total-sent", format(received - balance, "f"))
    wallet.add_attribute("total-transactions", str(summary["txs_total"]))
    first, last = _timestamp(summary.get("first_active")), _timestamp(summary.get("last_active"))
    if first:
        wallet.add_attribute("first-seen", first)
    if last:
        wallet.add_attribute("last-seen", last)
    wallet.add_attribute("last-updated", datetime.now(timezone.utc))
    unconfirmed = _coin(summary.get("unconfirmed_balance") or "0")
    if unconfirmed:
        wallet.add_attribute("text", f"Unconfirmed balance: {unconfirmed} {network}")
    return wallet


def _input(request):
    """(address, network or None, input uuid, input attribute or None) or an error message."""
    attribute = request.get("attribute")
    if attribute:
        if not check_input_attribute(attribute):
            return f"{standard_error_message}, which should contain at least a type, a value and an uuid."
        if attribute["type"] != "btc":
            return "Wrong input attribute type."
        return attribute["value"].strip(), "BTC", attribute["uuid"], attribute
    misp_object = request.get("object")
    if misp_object:
        if misp_object.get("name") != "coin-address":
            return "Wrong input object, a coin-address object is required."
        values = {a.get("object_relation"): a.get("value") for a in misp_object.get("Attribute", [])}
        address = values.get("address") or values.get("address-crypto")
        if not address:
            return "The coin-address object has no address."
        network = (values.get("symbol") or "").strip().upper() or None
        if network and network not in NETWORKS:
            return f"SoChain looks up BTC, LTC, DOGE and ZEC addresses, not {network}."
        return address.strip(), network, misp_object.get("uuid"), None
    return f"{standard_error_message}, or an object."


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    parsed = _input(request)
    if isinstance(parsed, str):
        return {"error": parsed}
    address, network, input_uuid, attribute = parsed
    if not ADDRESS.match(address):
        return {"error": f"{address} is not a cryptocurrency address."}
    # Clicking the magnifying glass asks for more than a hover.
    limit = 50 if request.get("persistent") == 1 else 5
    client = SoChain((request.get("config") or {}).get("apikey"))

    try:
        if network is None:
            network = client.detect_network(address)
            if network is None:
                return {"error": f"{address} is not a BTC, LTC, DOGE or ZEC address."}
        summary = client.get("address_summary", network, address)
        if summary is None:
            return {"error": f"{address} is not a valid {network} address."}
        counterparties = client.get("address_counterparties", network, address, limit=limit) or {}
        poisoning = client.get("address_poisoning", network, address, limit=limit) or {}
        wallet = _wallet(address, network, summary)
    except SoChainError as e:
        return {"error": str(e)}

    misp_event = MISPEvent()
    if attribute:
        input_attribute = MISPAttribute()
        input_attribute.from_dict(**attribute)
        misp_event.add_attribute(**input_attribute)
    if input_uuid:
        wallet.add_reference(input_uuid, "related-to")

    others = {}

    def other(other_address):
        if other_address == address:
            return wallet
        if other_address not in others:
            others[other_address] = _address_object(other_address, network)
        return others[other_address]

    for row in counterparties.get("counterparties") or []:
        if not row.get("address") or row["address"] == address:
            continue
        counterparty = other(row["address"])
        comment = f"{row.get('amount')} {network} in {row.get('txid')} at block {row.get('height')}"
        if row.get("direction") == "sent":
            wallet.add_reference(counterparty.uuid, "paid", comment=comment)
        else:
            counterparty.add_reference(wallet.uuid, "paid", comment=comment)

    findings = poisoning.get("findings") or []
    for finding in findings:
        if not finding.get("sender") or finding["sender"] == address:
            continue
        lookalike = other(finding["sender"])
        if not lookalike.get_attributes_by_relation("text"):
            lookalike.add_attribute("text", "Address poisoning: a look-alike address that sent dust")
        lookalike.add_reference(
            wallet.uuid, "paid", comment=f"{finding.get('amount')} {network} of dust in {finding.get('dust_txid')}"
        )
        if finding.get("imitates"):
            lookalike.add_reference(
                other(finding["imitates"]).uuid,
                "impersonates",
                comment=(
                    f"Shares the first {finding.get('shared_prefix')} and last {finding.get('shared_suffix')}"
                    " characters"
                ),
            )
    if findings:
        senders = len({f.get("sender") for f in findings if f.get("sender")})
        wallet.add_attribute("text", f"Targeted by address poisoning: {senders} look-alike address(es) sent it dust")
    if poisoning.get("building") or counterparties.get("building"):
        wallet.add_attribute(
            "text", "SoChain is still catching up on this network's history; findings may be incomplete"
        )

    misp_event.add_object(wallet)
    for misp_object in others.values():
        misp_event.add_object(misp_object)
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
