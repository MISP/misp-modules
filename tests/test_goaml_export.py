import base64
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import pytest
from pymisp import MISPEvent, MISPObject

from misp_modules.modules.export_mod import goamlexport as export


@pytest.fixture
def event():
    event = MISPEvent()
    event.info = "GoAML metadata regression test"
    event.timestamp = datetime(2018, 2, 22, 8, 34, 16, tzinfo=timezone.utc)
    transaction = MISPObject("transaction")
    for relation, value in {
        "transaction-number": "TW00000901",
        "date": "2015-12-01T10:03:00",
        "amount": "12345",
        "transmode-code": "BG",
        "from-funds-code": "E",
        "from-country": "FRA",
        "to-funds-code": "K",
        "to-country": "LUX",
    }.items():
        transaction.add_attribute(relation, value=value)
    bank = MISPObject("bank-account")
    bank.add_attribute("account", value="31032027088")
    bank.add_attribute("currency-code", value="EUR")
    bank.add_attribute("report-code", value="STR Suspicious Transaction Report")
    signatory = MISPObject("person")
    signatory.add_attribute("first-name", value="Nick")
    recipient = MISPObject("person")
    recipient.add_attribute("first-name", value="Jean")
    bank.add_reference(signatory.uuid, "signatory", Object={"name": signatory.name})
    transaction.add_reference(bank.uuid, "from", Object={"name": bank.name})
    transaction.add_reference(recipient.uuid, "to_my_client", Object={"name": recipient.name})
    for obj in (transaction, bank, signatory, recipient):
        event.add_object(obj)
    return event


def run(event, config):
    return export.handler(json.dumps({"data": [json.loads(event.to_json())], "config": config}))


def document(event, config):
    result = run(event, config)
    assert "error" not in result, result
    return ET.fromstring(base64.b64decode(result["data"], validate=True))


def remove_relation(event, relation):
    for obj in event.objects:
        obj.Attribute = [attribute for attribute in obj.attributes if attribute.object_relation != relation]


def add_bank(event, report_code=None, currency=None):
    bank = MISPObject("bank-account")
    if report_code is not None:
        bank.add_attribute("report-code", value=report_code)
    if currency is not None:
        bank.add_attribute("currency-code", value=currency)
    event.add_object(bank)


def test_legacy_configuration_and_transaction_content(event):
    before = datetime.now(timezone.utc).replace(microsecond=0)
    tree = document(event, {"rentity_id": "2510"})
    after = datetime.now(timezone.utc)
    assert tree.findtext("rentity_id") == "2510"
    assert tree.findtext("submission_code") == "E"
    assert tree.findtext("report_code") == "STR"
    assert tree.findtext("currency_code_local") == "EUR"
    date = datetime.fromisoformat(tree.findtext("submission_date"))
    assert before <= date <= after
    assert date.utcoffset() == timedelta(0)
    assert date != event.timestamp
    assert tree.findtext("transaction/transactionnumber") == "TW00000901"
    assert tree.findtext("transaction/amount_local") == "12345"
    assert tree.findtext("transaction/t_from/from_account/currency_code") == "EUR"
    assert tree.findtext("transaction/t_to_my_client/to_person/first_name") == "Jean"
    assert [node.tag for node in tree][:5] == [
        "rentity_id",
        "submission_code",
        "report_code",
        "submission_date",
        "currency_code_local",
    ]


def test_explicit_report_metadata_wins_without_converting_account_or_amount(event):
    tree = document(
        event,
        {
            "rentity_id": 42,
            "submission_code": "A",
            "report_code": "CTR",
            "submission_date": "2026-10-28T14:12:34+02:00",
            "currency_code_local": "usd",
        },
    )
    assert tree.findtext("rentity_id") == "42"
    assert tree.findtext("submission_code") == "A"
    assert tree.findtext("report_code") == "CTR"
    assert tree.findtext("submission_date") == "2026-10-28T14:12:34+02:00"
    assert tree.findtext("currency_code_local") == "USD"
    assert tree.findtext("transaction/t_from/from_account/currency_code") == "EUR"
    assert tree.findtext("transaction/amount_local") == "12345"


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        "2510",
        [],
        {"rentity_id": None},
        {"rentity_id": " "},
        {"rentity_id": 0},
        {"rentity_id": -1},
        {"rentity_id": True},
        {"rentity_id": "１２"},
        {"rentity_id": "<entity>"},
    ],
)
def test_missing_or_invalid_entity_returns_actionable_error(event, config):
    result = run(event, config)
    assert "rentity_id" in result["error"]
    assert "data" not in result


def test_absent_config_does_not_raise(event):
    result = export.handler(json.dumps({"data": [json.loads(event.to_json())]}))
    assert "rentity_id" in result["error"]


@pytest.mark.parametrize(
    "config,field",
    [
        ({"submission_code": True}, "submission_code"),
        ({"submission_code": "E Electronic"}, "submission_code"),
        ({"report_code": "STR Suspicious"}, "report_code"),
        ({"report_code": "STR\x00"}, "report_code"),
        ({"currency_code_local": "EURO"}, "currency_code_local"),
        ({"currency_code_local": "12A"}, "currency_code_local"),
        ({"submission_date": "2026-02-30T12:00:00Z"}, "submission_date"),
        ({"submission_date": "2026-10-28"}, "submission_date"),
        ({"submission_date": "20261028T120000"}, "submission_date"),
        ({"submission_date": "2026-10-28T12:00:00+15:00"}, "submission_date"),
        ({"submission_date": "2026-10-28T12:00:00+00:60"}, "submission_date"),
    ],
)
def test_invalid_explicit_metadata_is_not_silently_replaced(event, config, field):
    result = run(event, {"rentity_id": "2510", **config})
    assert field in result["error"]
    assert "data" not in result


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-10-28T12:00:00Z", "2026-10-28T12:00:00+00:00"),
        ("2026-10-28T12:00:00", "2026-10-28T12:00:00"),
        ("2026-10-28T12:00:00.123456-04:00", "2026-10-28T12:00:00.123456-04:00"),
    ],
)
def test_submission_date_override(event, value, expected):
    assert document(event, {"rentity_id": "2510", "submission_date": value}).findtext("submission_date") == expected


def test_str_precedence_and_most_frequent_report_code(event):
    add_bank(event, "CTR Cash Transaction Report", "EUR")
    add_bank(event, "CTR Cash Transaction Report", "EUR")
    assert document(event, {"rentity_id": "2510"}).findtext("report_code") == "STR"
    for obj in event.objects:
        for attribute in obj.get_attributes_by_relation("report-code"):
            if attribute.value.startswith("STR"):
                attribute.value = "UTR Unusual Transaction Report"
    assert document(event, {"rentity_id": "2510"}).findtext("report_code") == "CTR"


def test_currency_inference_is_independent_of_report_code(event, capsys):
    remove_relation(event, "report-code")
    assert document(event, {"rentity_id": "2510", "report_code": "CTR"}).findtext("currency_code_local") == "EUR"
    assert capsys.readouterr().out == ""


def test_report_inference_is_independent_of_currency(event):
    remove_relation(event, "currency-code")
    assert document(event, {"rentity_id": "2510", "currency_code_local": "EUR"}).findtext("report_code") == "STR"


@pytest.mark.parametrize("relation,field", [("report-code", "report_code"), ("currency-code", "currency_code_local")])
def test_missing_metadata_requires_explicit_configuration(event, relation, field):
    remove_relation(event, relation)
    result = run(event, {"rentity_id": "2510"})
    assert field in result["error"]
    assert "data" not in result


def test_mixed_account_currencies_require_explicit_local_currency(event):
    add_bank(event, currency="USD")
    add_bank(event, currency="EUR")  # A majority must not decide the denomination of amount_local.
    result = run(event, {"rentity_id": "2510"})
    assert "currency_code_local" in result["error"]
    assert "data" not in result
    assert (
        document(event, {"rentity_id": "2510", "currency_code_local": "GBP"}).findtext("currency_code_local") == "GBP"
    )


def test_metadata_does_not_require_bank_accounts_or_persons():
    event = MISPEvent()
    event.info = "Entity transaction"
    transaction = MISPObject("transaction")
    transaction.add_attribute("transaction-number", value="entity-transfer-1")
    transaction.add_attribute("amount", value="42")
    for direction in ("from", "to"):
        transaction.add_attribute(f"{direction}-funds-code", value="E")
        transaction.add_attribute(f"{direction}-country", value="LUX")
        entity = MISPObject("legal-entity")
        entity.add_attribute("name", value=direction)
        event.add_object(entity)
        transaction.add_reference(entity.uuid, direction, Object={"name": entity.name})
    event.add_object(transaction)
    tree = document(event, {"rentity_id": "2510", "report_code": "STR", "currency_code_local": "EUR"})
    assert tree.findtext("transaction/t_from/from_entity/name") == "from"
    assert tree.findtext("transaction/t_to/to_entity/name") == "to"


def test_optional_empty_configuration_uses_defaults_and_is_discoverable(event):
    tree = document(
        event,
        {
            "rentity_id": " 2510 ",
            "submission_code": " ",
            "submission_date": "",
            "report_code": None,
            "currency_code_local": "",
        },
    )
    assert tree.findtext("submission_code") == "E"
    assert tree.findtext("report_code") == "STR"
    assert export.version()["config"] == [
        "rentity_id",
        "submission_code",
        "submission_date",
        "currency_code_local",
        "report_code",
    ]
    assert export.introspection()["outputFileExtension"] == "xml"
