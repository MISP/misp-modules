import json
import socket
from unittest.mock import patch

import phonenumbers
import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import phone_number_info

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def _request(value="+44 20 8366 1177", attribute_type="phone-number", config=None):
    return {
        "module": "phone_number_info",
        "attribute": {"type": attribute_type, "value": value, "uuid": UUID},
        "config": config or {},
    }


def _run(request):
    return phone_number_info.handler(json.dumps(request))


def _phone(result):
    assert "error" not in result, result
    objects = result["results"]["Object"]
    assert len(objects) == 1
    assert objects[0]["name"] == "phone-number"
    return objects[0]


def _values(phone):
    return {attribute["object_relation"]: attribute["value"] for attribute in phone["Attribute"]}


@pytest.mark.parametrize("attribute_type", ["phone-number", "whois-registrant-phone"])
def test_normalizes_and_preserves_source_with_linked_template_valid_object(attribute_type):
    request = _request(attribute_type=attribute_type)
    request["attribute"].update(comment="Keep this", to_ids=True, Tag=[{"name": "tlp:amber"}])
    original = json.dumps(request)
    result = _run(request)
    phone = _phone(result)
    values = _values(phone)
    assert values["phone-number"] == "+442083661177"
    assert values["country-code"] == "GB"
    assert values["country-code-numeric"] == "+44"
    assert "Numbering-plan area: London" in values["text"]
    assert "Number type: FIXED_LINE" in values["text"]
    assert "Possible time zones: Europe/London" in values["text"]
    assert "Possible: true" in values["text"]
    assert "Valid according to numbering plan: true" in values["text"]
    assert f"Metadata source: phonenumbers {phonenumbers.__version__}" in values["text"]
    assert "not the subscriber's physical location" in values["text"]
    assert all(attribute["to_ids"] is False for attribute in phone["Attribute"])
    assert all(
        attribute["disable_correlation"] is True for attribute in phone["Attribute"] if attribute["type"] == "text"
    )
    assert phone["ObjectReference"][0]["referenced_uuid"] == UUID
    assert phone["ObjectReference"][0]["relationship_type"] == "derived-from"
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["type"] == attribute_type
    assert source["value"] == request["attribute"]["value"]
    assert source["comment"] == "Keep this"
    assert source["to_ids"] is True
    assert source["Tag"] == [{"name": "tlp:amber"}]
    assert json.dumps(request) == original
    parsed = MISPObject("phone-number", strict=True)
    parsed.from_dict(**phone)
    parsed.to_json(strict=True)


@pytest.mark.parametrize("value", ["020 8366 1177", "00 44 20 8366 1177"])
def test_national_numbers_and_idd_prefixes_need_an_explicit_origin_region(value):
    assert "default_region" in _run(_request(value))["error"]
    phone = _phone(_run(_request(value, config={"default_region": " gb "})))
    assert _values(phone)["phone-number"] == "+442083661177"


def test_preserves_extension_separately_from_e164():
    values = _values(_phone(_run(_request("+44 20 8366 1177 ext. 123"))))
    assert values["phone-number"] == "+442083661177"
    assert "Extension: 123" in values["text"]
    assert "Original input: +44 20 8366 1177 ext. 123" in values["text"]


def test_original_carrier_is_identified_and_portability_limitation_is_explicit():
    values = _values(_phone(_run(_request("+40721234567"))))
    assert "Number type: MOBILE" in values["text"]
    assert "Original carrier: Vodafone" in values["text"]
    assert "may differ from the current operator after number portability" in values["text"]
    assert "Validity does not establish assignment, reachability or ownership" in values["text"]


def test_language_controls_geographic_description():
    values = _values(_phone(_run(_request("+41431234567", config={"language": "de"}))))
    assert "Numbering-plan area: Zürich" in values["text"]


def test_shared_calling_code_uses_full_number_to_identify_region():
    values = _values(_phone(_run(_request("+14165551234"))))
    assert values["country-code"] == "CA"
    assert values["country-code-numeric"] == "+1"


def test_non_geographic_number_does_not_invent_a_country_or_timezone():
    values = _values(_phone(_run(_request("+80012345678"))))
    assert "country-code" not in values
    assert values["country-code-numeric"] == "+800"
    assert "Number type: TOLL_FREE" in values["text"]
    assert "Numbering-plan area: Unknown" in values["text"]
    assert "Original carrier: Unknown" in values["text"]
    assert "Possible time zones: Unknown" in values["text"]
    assert "Etc/Unknown" not in values["text"]


def test_missing_optional_metadata_does_not_discard_valid_number():
    with (
        patch.object(phone_number_info.geocoder, "description_for_number", return_value=""),
        patch.object(phone_number_info.carrier, "name_for_number", return_value=""),
        patch.object(phone_number_info.timezone, "time_zones_for_number", return_value=("Etc/Unknown",)),
    ):
        values = _values(_phone(_run(_request())))
    assert values["phone-number"] == "+442083661177"
    assert "Numbering-plan area: Unknown" in values["text"]
    assert "Original carrier: Unknown" in values["text"]
    assert "Possible time zones: Unknown" in values["text"]


def test_all_possible_time_zones_are_preserved():
    zones = ("Europe/London", "Atlantic/Reykjavik")
    with patch.object(phone_number_info.timezone, "time_zones_for_number", return_value=zones):
        values = _values(_phone(_run(_request())))
    assert "Possible time zones: Europe/London, Atlantic/Reykjavik" in values["text"]


@pytest.mark.parametrize(("value", "possible"), [("+12001230101", "true"), ("+123", "false")])
def test_invalid_number_returns_diagnostic_without_normalized_object(value, possible):
    result = _run(_request(value))
    assert "error" not in result
    assert result["results"]["Object"] == []
    source, diagnostic = result["results"]["Attribute"]
    assert source["uuid"] == UUID and source["value"] == value
    assert diagnostic["type"] == "text"
    assert f"Possible: {possible}" in diagnostic["value"]
    assert "Valid according to numbering plan: false" in diagnostic["value"]
    assert "No normalized phone-number object was created" in diagnostic["value"]
    assert diagnostic["to_ids"] is False and diagnostic["disable_correlation"] is True
    assert UUID in diagnostic["comment"]


@pytest.mark.parametrize("value", [None, 123456, "", "   "])
def test_invalid_value_returns_error(value):
    assert "error" in _run(_request(value))


@pytest.mark.parametrize("value", ["garbage", "+not-a-number"])
def test_unparseable_number_returns_error(value):
    assert "error" in _run(_request(value, config={"default_region": "GB"}))


@pytest.mark.parametrize("raw", [None, True, "{", "[]", "null", '"number"'])
def test_malformed_request_returns_error(raw):
    assert "error" in phone_number_info.handler(raw)


@pytest.mark.parametrize("attribute", [None, [], "number", {}, {"type": "phone-number", "value": "+442083661177"}])
def test_missing_or_malformed_attribute_returns_error(attribute):
    request = _request()
    request["attribute"] = attribute
    assert "error" in _run(request)


def test_unsupported_attribute_returns_error():
    assert "error" in _run(_request(attribute_type="text"))


@pytest.mark.parametrize(
    "config",
    [[], "GB", False, {"default_region": "ZZ"}, {"default_region": 44}, {"language": 1}, {"language": "  "}],
)
def test_invalid_configuration_returns_error(config):
    request = _request()
    request["config"] = config
    assert "error" in _run(request)


@pytest.mark.parametrize("config", [None, {}, {"language": "", "default_region": ""}])
def test_empty_configuration_uses_defaults_for_international_numbers(config):
    request = _request()
    request["config"] = config
    assert _values(_phone(_run(request)))["phone-number"] == "+442083661177"


def test_lookup_requires_no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Phone-number lookup attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert "Original carrier: Vodafone" in _values(_phone(_run(_request("+40721234567"))))["text"]


def test_metadata_and_no_query_contract():
    assert phone_number_info.handler() is False
    assert phone_number_info.introspection()["format"] == "misp_standard"
    assert phone_number_info.version()["config"] == ["default_region", "language"]
