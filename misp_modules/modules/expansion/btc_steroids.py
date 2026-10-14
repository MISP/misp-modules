import json
import time
from datetime import datetime, timezone

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["btc"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.3",
    "author": "Sascha Rommelfangen",
    "description": "An expansion hover module to get a blockchain balance from a BTC address in MISP.",
    "module-type": ["hover"],
    "name": "BTC Steroids",
    "logo": "bitcoin.png",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "btc address attribute.",
    "output": "A btc-wallet object and one btc-transaction object per transaction the address took part in.",
}

moduleconfig = []

blockchain_firstseen = "https://blockchain.info/q/addressfirstseen/"
blockchain_balance = "https://blockchain.info/q/addressbalance/"
blockchain_totalreceived = "https://blockchain.info/q/getreceivedbyaddress/"
blockchain_all = "https://blockchain.info/rawaddr/{}?filter=5{}"
converter = "https://min-api.cryptocompare.com/data/pricehistorical?fsym=BTC&tsyms=USD,EUR&ts={}"
converter_rls = "https://min-api.cryptocompare.com/stats/rate/limit"
g_rate_limit = 300
start_time = 0
conversion_rates = {}

SATOSHI = 100000000


def get_consumption(output=False):
    try:
        req = requests.get(converter_rls)
        jreq = req.json()
        minute = str(jreq["Data"]["calls_left"]["minute"])
        hour = str(jreq["Data"]["calls_left"]["hour"])
    except Exception:
        minute = str(-1)
        hour = str(-1)
    # Debug out for the console
    print("Calls left this minute / hour: " + minute + " / " + hour)
    return minute, hour


def convert(btc, timestamp):
    """Convert a BTC amount to USD and EUR at the rate of the given day, or
    (None, None) when the rate could not be fetched."""
    global g_rate_limit
    global start_time
    date = time.strftime("%Y-%m-%d", time.localtime(timestamp))
    # Lookup conversion rates in the cache:
    if date in conversion_rates:
        usd, eur = conversion_rates[date]
    else:
        # If not cached, we have to get the conversion rates
        # We have to be careful with rate limiting on the server side
        if g_rate_limit == 300:
            minute, hour = get_consumption()
        g_rate_limit -= 1
        if g_rate_limit <= 10:
            minute, hour = get_consumption(output=True)
            if int(minute) <= 10:
                time.sleep(3)
            else:
                start_time = time.time()
                g_rate_limit = int(minute)
        try:
            req = requests.get(converter.format(timestamp))
            jreq = req.json()
            usd = jreq["BTC"]["USD"]
            eur = jreq["BTC"]["EUR"]
            # Since we have the rates, store them in the cache
            conversion_rates[date] = (usd, eur)
        except Exception as ex:
            print(ex)
            get_consumption(output=True)
            return None, None
    return usd * btc, eur * btc


def _net_value(transaction, btc):
    """What a transaction moved for this wallet, in BTC: what it received minus
    what it spent. Negative when the wallet was the sender."""
    received = sum(out.get("value") or 0 for out in transaction.get("out") or [] if out.get("addr") == btc)
    spent = sum(
        (tx.get("prev_out") or {}).get("value") or 0
        for tx in transaction.get("inputs") or []
        if (tx.get("prev_out") or {}).get("addr") == btc
    )
    return (received - spent) / SATOSHI


def _counterparties(transaction, btc):
    """The other addresses in the transaction: who the wallet received from and
    who it sent to, in the order blockchain.info lists them."""
    addresses = [(tx.get("prev_out") or {}).get("addr") for tx in transaction.get("inputs") or []]
    addresses += [out.get("addr") for out in transaction.get("out") or []]
    counterparties = []
    for address in addresses:
        if address and address != btc and address not in counterparties:
            counterparties.append(address)
    return counterparties


def _iter_transactions(btc, jreq, click):
    """The transactions blockchain.info knows about: all of them when the
    magnifying glass was clicked, the 5 most recent on a simple hover.

    The first page arrived together with the balance, so only the pages after
    it are fetched."""
    n_tx = jreq["n_tx"] if click else min(jreq["n_tx"], 5)
    page = (jreq.get("txs") or [])[:n_tx]
    yield from page
    offset = len(page)
    while offset < n_tx:
        if not page:
            return
        try:
            req = requests.get(blockchain_all.format(btc, f"&limit=50&offset={offset}"))
        except Exception as e:
            # Lazy retry - cries for a function
            print(e)
            time.sleep(3)
            req = requests.get(blockchain_all.format(btc, f"&limit=50&offset={offset}"))
        page = (req.json().get("txs") or [])[: n_tx - offset]
        yield from page
        offset += len(page)


def _parse_wallet(jreq, btc):
    wallet = MISPObject("btc-wallet")
    wallet.add_attribute("wallet-address", btc)
    wallet.add_attribute("balance_BTC", jreq["final_balance"] / SATOSHI)
    wallet.add_attribute("BTC_received", jreq["total_received"] / SATOSHI)
    wallet.add_attribute("BTC_sent", jreq["total_sent"] / SATOSHI)
    return wallet


def _parse_transaction(transaction, btc):
    misp_object = MISPObject("btc-transaction")
    # The wallet being described first, then whoever it exchanged value with.
    misp_object.add_attribute("btc-address", btc)
    for counterparty in _counterparties(transaction, btc):
        misp_object.add_attribute("btc-address", counterparty)
    if transaction.get("hash"):
        misp_object.add_attribute("transaction-number", transaction["hash"])
    value = _net_value(transaction, btc)
    misp_object.add_attribute("value_BTC", value)
    if transaction.get("time"):
        misp_object.add_attribute("time", datetime.fromtimestamp(int(transaction["time"]), tz=timezone.utc))
        usd, eur = convert(value, transaction["time"])
        if usd is not None:
            misp_object.add_attribute("value_USD", usd)
        if eur is not None:
            misp_object.add_attribute("value_EUR", eur)
    return misp_object


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] != "btc":
        return {"error": "Wrong input attribute type."}
    btc = attribute["value"]
    # This means the magnifying glass has been clicked, rather than the
    # attribute only being hovered over.
    click = request.get("persistent") == 1

    try:
        req = requests.get(blockchain_all.format(btc, "&limit=50"))
        jreq = req.json()
    except Exception:
        return {"error": "Not able to reach blockchain.info."}
    if "n_tx" not in jreq:
        return {"error": f"{btc} is not a valid BTC address."}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    wallet = _parse_wallet(jreq, btc)
    wallet.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(wallet)

    for transaction in _iter_transactions(btc, jreq, click):
        misp_object = _parse_transaction(transaction, btc)
        misp_object.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
