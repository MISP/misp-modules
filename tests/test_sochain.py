import json
from unittest.mock import patch

import requests

from misp_modules.modules.expansion import sochain

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
BTC = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj"
PAID = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPPz"
PAYER = "bc1q368c8ue4p3c6pty3k0m7zu6jndspx23x3a78r9r9jyekffeqhdlqkd5dl0"
LOOKALIKE = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPZz"
DOGE = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"

# Shaped as SoChain answered on 23 Oct 2026, cut to a few rows.
SUMMARY = {
    "txs_sent": 1796,
    "txs_received": 32014,
    "txs_total": 32014,
    "confirmed_balance": "0.12771030",
    "unconfirmed_balance": "0.00000000",
    "confirmed_received": "285785.38685032",
    "first_active": {"height": 687848, "time": 1623874601},
    "last_active": {"height": 972455, "time": 1792576976},
}
COUNTERPARTIES = {
    "address": BTC,
    "window_blocks": 4320,
    "from_height": 968436,
    "building": False,
    "counterparties": [
        {"address": PAID, "direction": "sent", "amount": "0.01017653", "txid": "95" * 32, "height": 972455},
        {"address": PAYER, "direction": "received", "amount": "0.01017653", "txid": "0b" * 32, "height": 972446},
    ],
}
POISONING = {
    "address": BTC,
    "building": False,
    "findings": [
        {
            "dust_txid": "dd" * 32,
            "amount": "0.00000546",
            "sender": LOOKALIKE,
            "imitates": PAID,
            "real_txid": "95" * 32,
            "real_height": 972455,
            "real_amount": "0.01017653",
            "receiver_paid": False,
            "shared_prefix": 4,
            "shared_suffix": 4,
            "sender_kind": "new",
            "sender_txs": 1,
            "height": 972460,
            "confirmed": True,
        }
    ],
}


class MockResponse:
    def __init__(self, data=None, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {"status": "success", "data": data}

    def json(self):
        return self.payload


def _answers(valid_on=("BTC",), summary=SUMMARY, counterparties=COUNTERPARTIES, poisoning=POISONING):
    calls = []

    def get(url, headers=None, params=None, timeout=None):
        calls.append((url, headers, params))
        endpoint, network = url.split("/api/v3/")[1].split("/")[:2]
        if endpoint == "is_valid_address":
            return MockResponse({"is_valid": network in valid_on})
        answer = {
            "address_summary": summary,
            "address_counterparties": counterparties,
            "address_poisoning": poisoning,
        }[endpoint]
        return answer if isinstance(answer, MockResponse) else MockResponse(answer)

    return get, calls


def _run(request, **answers):
    get, calls = _answers(**answers)
    with patch.object(sochain.requests, "get", side_effect=get):
        return sochain.handler(json.dumps(request)), calls


def _attribute_request(value=BTC, config=None, **extra):
    return {
        "module": "sochain",
        "attribute": {"type": "btc", "value": value, "uuid": UUID},
        "config": config or {},
        **extra,
    }


def _object_request(address, symbol=None):
    attributes = [{"object_relation": "address-crypto", "value": address, "type": "text"}]
    if symbol:
        attributes.append({"object_relation": "symbol", "value": symbol, "type": "text"})
    return {
        "module": "sochain",
        "object": {"name": "coin-address", "uuid": UUID, "Attribute": attributes},
        "config": {},
    }


def _objects(result):
    return result["results"]["Object"]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def _by_address(result):
    return {next(v for r, v in _values(o) if r in ("address", "address-crypto")): o for o in _objects(result)}


def test_btc_attribute_gets_the_address_summary():
    result, calls = _run(_attribute_request())
    wallet = _by_address(result)[BTC]
    values = _values(wallet)
    assert ("address", BTC) in values
    assert ("symbol", "BTC") in values
    assert ("current-balance", "0.12771030") in values
    assert ("total-received", "285785.38685032") in values
    # received minus balance, exactly
    assert ("total-sent", "285785.25914002") in values
    assert ("total-transactions", "32014") in values
    relations = {r for r, _ in values}
    assert {"first-seen", "last-seen", "last-updated"} <= relations
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in wallet["ObjectReference"]][0] == (
        UUID,
        "related-to",
    )
    # a btc attribute is a Bitcoin address: no network detection
    assert not any("is_valid_address" in url for url, _, _ in calls)
    assert result["results"]["Attribute"][0]["value"] == BTC


def test_counterparties_are_linked_with_paid_references():
    result, _ = _run(_attribute_request())
    objects = _by_address(result)
    wallet = objects[BTC]
    sent = [r for r in wallet["ObjectReference"] if r["relationship_type"] == "paid"]
    assert [r["referenced_uuid"] for r in sent] == [objects[PAID]["uuid"]]
    assert sent[0]["comment"] == f"0.01017653 BTC in {'95' * 32} at block 972455"
    received = [r for r in objects[PAYER]["ObjectReference"] if r["relationship_type"] == "paid"]
    assert [r["referenced_uuid"] for r in received] == [wallet["uuid"]]


def test_address_poisoning_lookalike_impersonates_the_real_address():
    result, _ = _run(_attribute_request())
    objects = _by_address(result)
    lookalike = objects[LOOKALIKE]
    references = {(r["relationship_type"], r["referenced_uuid"]) for r in lookalike["ObjectReference"]}
    assert ("impersonates", objects[PAID]["uuid"]) in references
    assert ("paid", objects[BTC]["uuid"]) in references
    assert ("text", "Targeted by address poisoning: 1 look-alike address(es) sent it dust") in _values(objects[BTC])


def test_no_findings_add_no_poisoning_text():
    result, _ = _run(_attribute_request(), poisoning={"address": BTC, "building": False, "findings": []})
    objects = _by_address(result)
    assert set(objects) == {BTC, PAID, PAYER}
    assert not any(r == "text" for r, _ in _values(objects[BTC]))


def test_hover_asks_for_5_rows_and_click_for_50():
    _, calls = _run(_attribute_request())
    assert {p["limit"] for url, _, p in calls if "counterparties" in url or "poisoning" in url} == {5}
    _, calls = _run(_attribute_request(persistent=1))
    assert {p["limit"] for url, _, p in calls if "counterparties" in url or "poisoning" in url} == {50}


def test_api_key_is_sent_only_when_set():
    _, calls = _run(_attribute_request())
    assert all("API-KEY" not in headers for _, headers, _ in calls)
    _, calls = _run(_attribute_request(config={"apikey": "my-key"}))
    assert all(headers["API-KEY"] == "my-key" for _, headers, _ in calls)


def test_coin_address_object_without_symbol_detects_the_network():
    result, calls = _run(_object_request(DOGE), valid_on=("DOGE",))
    tried = [url.split("/")[-2] for url, _, _ in calls if "is_valid_address" in url]
    # a D address is tried on Dogecoin first
    assert tried == ["DOGE"]
    wallet = _by_address(result)[DOGE]
    assert ("symbol", "DOGE") in _values(wallet)
    assert ("address-crypto", DOGE) in _values(wallet)
    assert all("/DOGE/" in url for url, _, _ in calls)


def test_coin_address_object_symbol_picks_the_network():
    result, calls = _run(_object_request(DOGE, symbol="ltc"), valid_on=())
    assert not any("is_valid_address" in url for url, _, _ in calls)
    assert all("/LTC/" in url for url, _, _ in calls)


def test_unsupported_symbol_returns_error():
    result, calls = _run(_object_request(DOGE, symbol="XMR"))
    assert "error" in result and not calls


def test_address_valid_nowhere_returns_error():
    result, calls = _run(_object_request("Xnotanaddress"), valid_on=())
    assert "error" in result
    assert len(calls) == len(sochain.NETWORKS)


def test_unknown_address_returns_error():
    fail = MockResponse(status_code=404, payload={"status": "fail", "data": {"error_message": "Invalid address?"}})
    result, _ = _run(_attribute_request(), summary=fail)
    assert "error" in result


def test_network_without_poisoning_check_still_returns_the_summary():
    fail = MockResponse(status_code=404, payload={"status": "fail", "data": {"error_message": "Not available."}})
    result, _ = _run(_attribute_request(), poisoning=fail)
    assert BTC in _by_address(result)


def test_rate_limit_and_bad_key_name_the_dashboard():
    for status in (401, 429):
        response = MockResponse(status_code=status, payload={"status": "fail", "data": {"error_message": "x"}})
        result, _ = _run(_attribute_request(), summary=response)
        assert "https://sochain.com/dashboard" in result["error"]


def test_unreachable_api_returns_error():
    with patch.object(sochain.requests, "get", side_effect=requests.ConnectionError("down")):
        result = sochain.handler(json.dumps(_attribute_request()))
    assert result["error"].startswith("Not able to reach SoChain")


def test_wrong_attribute_type_returns_error():
    request = {
        "module": "sochain",
        "attribute": {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID},
    }
    result, calls = _run(request)
    assert "error" in result and not calls


def test_introspection_and_version():
    assert sochain.introspection() == sochain.mispattributes
    assert sochain.mispattributes["format"] == "misp_standard"
    assert sochain.version()["config"] == ["apikey"]


def test_zero_amounts_keep_their_decimals():
    empty = dict(SUMMARY, confirmed_balance="0.00000000", confirmed_received="0.00000000")
    result, _ = _run(_attribute_request(), summary=empty)
    values = _values(_by_address(result)[BTC])
    assert ("current-balance", "0.00000000") in values
    assert ("total-sent", "0.00000000") in values
