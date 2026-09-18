import json
from unittest.mock import patch

from misp_modules.modules.expansion import btc_steroids

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
BTC = "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"
OTHER = "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH"

_RAWADDR = {
    "address": BTC,
    "final_balance": 21268,
    "total_received": 74825,
    "total_sent": 53557,
    "n_tx": 2,
    "txs": [
        {
            "hash": "aa" * 32,
            "time": 1500000000,
            "inputs": [{"prev_out": {"addr": OTHER, "value": 100000}}],
            "out": [{"addr": BTC, "value": 74825}, {"addr": OTHER, "value": 25175}],
        },
        {
            "hash": "bb" * 32,
            "time": 1600000000,
            "inputs": [{"prev_out": {"addr": BTC, "value": 53557}}],
            "out": [{"addr": OTHER, "value": 53557}],
        },
    ],
}

_RATES = {"BTC": {"USD": 10000.0, "EUR": 9000.0}}


class MockResponse:
    def __init__(self, payload):
        self.payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self.payload


def _dispatch(url, *args, **kwargs):
    if "blockchain.info" in url:
        return MockResponse(_RAWADDR)
    if "pricehistorical" in url:
        return MockResponse(_RATES)
    return MockResponse({"Data": {"calls_left": {"minute": 100, "hour": 1000}}})


def _run(attribute, payload=_RAWADDR):
    query = json.dumps({"module": "btc_steroids", "attribute": attribute, "config": {}})
    with patch.object(btc_steroids, "requests") as mock_requests:
        mock_requests.get.side_effect = lambda url, *a, **k: (
            MockResponse(payload) if "blockchain.info" in url else _dispatch(url)
        )
        btc_steroids.conversion_rates.clear()
        return btc_steroids.handler(query)


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_wallet_object_carries_the_balances():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    result = _run(attribute)
    values = _values(_objects(result, "btc-wallet")[0])
    assert ("wallet-address", BTC) in values
    assert ("balance_BTC", "0.00021268") in values
    assert ("BTC_received", "0.00074825") in values
    assert ("BTC_sent", "0.00053557") in values


def test_one_transaction_object_per_transaction():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    transactions = _objects(_run(attribute), "btc-transaction")
    assert len(transactions) == 2
    numbers = {value for obj in transactions for relation, value in _values(obj) if relation == "transaction-number"}
    assert numbers == {"aa" * 32, "bb" * 32}


def test_received_and_spent_transactions_get_signed_values():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    transactions = _objects(_run(attribute), "btc-transaction")
    by_number = {next(v for r, v in _values(obj) if r == "transaction-number"): _values(obj) for obj in transactions}
    # received 74825 satoshi
    assert ("value_BTC", "0.00074825") in by_number["aa" * 32]
    # spent 53557 satoshi
    assert ("value_BTC", "-0.00053557") in by_number["bb" * 32]


def test_transactions_carry_their_counterparties():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    transactions = _objects(_run(attribute), "btc-transaction")
    received = next(obj for obj in transactions if ("transaction-number", "aa" * 32) in _values(obj))
    addresses = [a["value"] for a in received["Attribute"] if a["object_relation"] == "btc-address"]
    # the wallet first, then who it exchanged value with
    assert addresses[0] == BTC
    assert OTHER in addresses[1:]


def test_transactions_are_converted_to_usd_and_eur():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    transactions = _objects(_run(attribute), "btc-transaction")
    relations = {relation for obj in transactions for relation, _ in _values(obj)}
    assert "value_USD" in relations
    assert "value_EUR" in relations
    assert "time" in relations


def test_every_object_references_the_input_attribute():
    attribute = {"type": "btc", "value": BTC, "uuid": UUID}
    result = _run(attribute)
    for misp_object in result["results"]["Object"]:
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert references == [(UUID, "related-to")]


def test_invalid_address_returns_error():
    attribute = {"type": "btc", "value": "not-an-address", "uuid": UUID}
    result = _run(attribute, payload={"error": "unknown"})
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result = _run(attribute)
    assert "error" in result


def test_introspection_and_version():
    assert btc_steroids.introspection() == btc_steroids.mispattributes
    assert btc_steroids.mispattributes["format"] == "misp_standard"
    assert btc_steroids.version()["name"] == "BTC Steroids"
