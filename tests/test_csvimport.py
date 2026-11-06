import base64
import csv
import io
import json
from unittest.mock import patch

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.import_mod import csvimport


def _import(data, header, delimiter=""):
    request = {
        "data": base64.b64encode(data.encode()).decode(),
        "config": {"header": header, "has_header": "0", "special_delimiter": delimiter},
    }
    return csvimport.dict_handler(request)


def _attributes(result):
    return result["results"]["Attribute"]


def test_special_delimiter_keeps_commas_inside_fields():
    result = _import("1.2.3.4;seen in phishing, then C2\nevil,example.com;x\n", "ip-src,comment", ";")
    attributes = _attributes(result)
    assert [(a["value"], a["comment"]) for a in attributes] == [
        ("1.2.3.4", "seen in phishing, then C2"),
        ("evil,example.com", "x"),
    ]


def test_special_delimiter_honours_quoting():
    result = _import('"a;b.example";"note; with delimiter"\n', "domain,comment", ";")
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("a;b.example", "note; with delimiter")]


def test_multi_character_delimiter():
    result = _import("1.2.3.4||first, second\n", "ip-src,comment", "||")
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("1.2.3.4", "first, second")]


def test_empty_to_ids_cell():
    result = _import("ip-src,1.2.3.4,\nip-src,5.6.7.8,1\nip-src,9.9.9.9,0\n", "type,value,to_ids")
    to_ids = {a["value"]: a["to_ids"] for a in _attributes(result)}
    assert to_ids["5.6.7.8"] is True
    assert to_ids["9.9.9.9"] is False
    assert "1.2.3.4" in to_ids


def test_empty_to_ids_cell_with_type_columns():
    result = _import("1.2.3.4,\n", "ip-src,to_ids")
    assert [a["value"] for a in _attributes(result)] == ["1.2.3.4"]


def test_empty_category_cell():
    result = _import("ip-src,1.2.3.4,\nip-src,5.6.7.8,network activity\n", "type,value,category")
    categories = {a["value"]: a["category"] for a in _attributes(result)}
    assert categories["5.6.7.8"] == "Network activity"
    assert "1.2.3.4" in categories


def test_attribute_tag_column():
    result = _import('ip-src,1.2.3.4,"tlp:green, malware"\n', "type,value,attribute_tag")
    (attribute,) = _attributes(result)
    assert [tag["name"] for tag in attribute["Tag"]] == ["tlp:green", "malware"]
    assert "attribute_tag" not in attribute


def test_multi_character_delimiter_skips_blank_lines():
    result = _import("1.2.3.4||a.example\n\n5.6.7.8||b.example\n", "ip-src,domain", "||")
    assert [a["value"] for a in _attributes(result)] == ["1.2.3.4", "a.example", "5.6.7.8", "b.example"]


def request(data, config=None, **extra):
    return {"data": base64.b64encode(data.encode()).decode(), "config": config, **extra}


def test_issue_604_file_path_without_data_explains_upload_contract():
    body = {
        "module": "csvimport",
        "data": "",
        "file": "/var/www/MISP/ipblocklist.csv",
        "config": {"header": ",ip-dst,ip-dst|port,,datetime,malware-type", "has_header": 0, "special_delimiter": ","},
    }
    with patch("builtins.open") as open_file:
        result = csvimport.dict_handler(body)
    assert "base64-encoded UTF-8 CSV contents" in result["error"]
    assert "'file' field is not a server-side file path" in result["error"]
    open_file.assert_not_called()


def test_issue_604_encoded_contents_import_with_original_configuration():
    body = request(
        "ignored,192.0.2.1,192.0.2.1|443,ignored,2023-02-23T00:00:00Z,botnet\n",
        {"header": ",ip-dst,ip-dst|port,,datetime,malware-type", "has_header": 0, "special_delimiter": ","},
        file="/var/www/MISP/ipblocklist.csv",
    )
    result = csvimport.dict_handler(body)
    assert "error" not in result, result
    assert {a["type"] for a in _attributes(result)} == {"ip-dst", "ip-dst|port", "datetime", "malware-type"}
    assert any(a["value"] == "192.0.2.1" for a in _attributes(result))


@pytest.mark.parametrize("has_header", [True, 1, "1"])
@pytest.mark.parametrize(
    "optional", [{}, {"header": None, "special_delimiter": None}, {"header": "", "special_delimiter": ""}]
)
def test_header_from_csv_accepts_rest_flags_and_omitted_options(has_header, optional):
    body = request("ip-dst,comment\n192.0.2.1,example\n", {"has_header": has_header, **optional})
    result = csvimport.dict_handler(body)
    assert "error" not in result, result
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("192.0.2.1", "example")]


@pytest.mark.parametrize("has_header", [False, 0, "0", None, ""])
def test_explicit_header_and_false_flags_keep_first_data_row(has_header):
    result = csvimport.dict_handler(request("192.0.2.1\n192.0.2.2\n", {"header": "ip-dst", "has_header": has_header}))
    assert [a["value"] for a in _attributes(result)] == ["192.0.2.1", "192.0.2.2"]


@pytest.mark.parametrize("delimiter", [None, "", ",", ";", "\t", "||"])
def test_omitted_and_custom_delimiters(delimiter):
    separator = delimiter or ","
    result = csvimport.dict_handler(
        request(f"192.0.2.1{separator}example\n", {"header": "ip-dst,comment", "special_delimiter": delimiter})
    )
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("192.0.2.1", "example")]


def test_base64_line_wrapping_and_utf8_bom():
    encoded = base64.encodebytes("\ufeffip-dst,comment\n192.0.2.1,café\n".encode()).decode()
    result = csvimport.dict_handler({"data": encoded, "config": {"has_header": True}})
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("192.0.2.1", "café")]


@pytest.mark.parametrize("body", [None, [], "invalid", 1])
def test_invalid_request_object_returns_error(body):
    assert "JSON object" in csvimport.dict_handler(body)["error"]


@pytest.mark.parametrize("data", [None, "", "  ", 12, [], {}])
def test_missing_data_returns_input_guidance(data):
    assert "base64" in csvimport.dict_handler({"data": data})["error"]


@pytest.mark.parametrize("data", ["!!!", "abc", "192.0.2.1", "é"])
def test_invalid_base64_returns_input_error(data):
    assert "not valid base64" in csvimport.dict_handler({"data": data})["error"]


def test_invalid_utf8_returns_input_error():
    body = {"data": base64.b64encode(b"\xff\xfe").decode()}
    assert csvimport.dict_handler(body) == {"error": "Input is not valid UTF-8"}


@pytest.mark.parametrize("config", [[], 1, "invalid"])
def test_invalid_config_returns_input_error(config):
    assert "config must be a JSON object" in csvimport.dict_handler(request("192.0.2.1\n", config))["error"]


@pytest.mark.parametrize(
    "config, expected",
    [
        ({"header": []}, "comma-separated string"),
        ({"special_delimiter": 3}, "special_delimiter"),
        ({"special_delimiter": "\n"}, "special_delimiter"),
        ({"has_header": "invalid"}, "has_header"),
    ],
)
def test_invalid_options_return_input_errors(config, expected):
    assert expected in csvimport.dict_handler(request("192.0.2.1\n", config))["error"]


@pytest.mark.parametrize("config", [None, {}])
def test_missing_mapping_explains_header_requirement(config):
    assert "Provide a header" in csvimport.dict_handler(request("192.0.2.1\n", config))["error"]


@pytest.mark.parametrize(
    "data, config",
    [
        ("  \n\t\n", {"header": "ip-dst"}),
        ("\n# comment\n", {"header": "ip-dst"}),
        ("ip-dst\n", {"has_header": True}),
        ("ip-dst\n", {"header": "ip-dst", "has_header": True}),
    ],
)
def test_empty_and_header_only_csv_returns_input_error(data, config):
    assert "no data rows" in csvimport.dict_handler(request(data, config))["error"]


def test_errors_do_not_mutate_previous_responses():
    first = csvimport.dict_handler({"data": ""})
    message = first["error"]
    second = csvimport.dict_handler({"data": base64.b64encode(b"\xff").decode()})
    assert first["error"] == message
    assert first != second


@pytest.mark.parametrize("with_context", [False, True])
def test_standard_misp_csv_still_imports_attributes_and_objects(with_context):
    header = csvimport.misp_extended_csv_header if with_context else csvimport.misp_standard_csv_header
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    row = [
        "32876e4a-916d-4935-9e51-7b69a76718f8",
        "1",
        "Network activity",
        "ip-dst",
        "192.0.2.1",
        "example",
        "1",
        "1677158400",
        "",
        "tlp:green",
        "",
        "",
        "",
    ]
    context = [""] * (len(header) - len(row))
    writer.writerow(row + context)
    row[0] = "cb8bf166-ed67-433d-a211-4d3c475b5c07"
    row[8] = "ip"
    row[10] = "33de2bc3-f7a9-4577-b9dd-651ed135581b"
    row[11] = "domain-ip"
    writer.writerow(row + context)
    result = csvimport.dict_handler(request(output.getvalue(), {"has_header": True}))
    assert "error" not in result, result
    assert _attributes(result)[0]["to_ids"] is True
    assert _attributes(result)[0]["Tag"][0]["name"] == "tlp:green"
    obj = result["results"]["Object"][0]
    assert obj["name"] == "domain-ip"
    assert obj["Attribute"][0]["value"] == "192.0.2.1"


class TestCSVImportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"csvimport": csvimport, "type:csvimport": "import_mod"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_discovery_and_base64_csv_request(self):
        discovered = json.loads(self.fetch("/modules").body)[0]
        assert discovered["type"] == "import_mod"
        assert discovered["mispattributes"]["format"] == "misp_standard"
        body = request("ip-dst\n192.0.2.1\n", {"has_header": 1}, module="csvimport")
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        assert [a["value"] for a in _attributes(json.loads(response.body))] == ["192.0.2.1"]

    def test_file_path_request_returns_actionable_error(self):
        body = {"module": "csvimport", "data": "", "file": "/var/www/MISP/ipblocklist.csv"}
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        result = json.loads(response.body)
        assert "base64-encoded UTF-8 CSV contents" in result["error"]
        assert "Unsupported attributes type" not in result["error"]
