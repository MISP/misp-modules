import builtins
import json
from importlib import resources
from unittest.mock import Mock, patch
from urllib.parse import quote

import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import duckduckgo_search as module

SOURCE_UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
VALUE = "https://example.com/é?x=1&y=2"
ROW = {"href": "https://example.org/report", "title": "A report", "body": "An example snippet."}


def query(value=VALUE, kind="url", config=None, **changes):
    payload = {
        "attribute": {"type": kind, "value": value, "uuid": SOURCE_UUID, "to_ids": True, "comment": "original"},
        "config": config,
    }
    payload.update(changes)
    return json.dumps(payload)


@pytest.fixture
def client():
    with patch("ddgs.DDGS") as factory:
        instance = factory.return_value.__enter__.return_value
        instance.text.return_value = [ROW]
        yield factory, instance


def test_search_results_preserve_source_and_use_valid_annotation_template(client):
    factory, instance = client
    result = module.handler(query())
    instance.text.assert_called_once_with(VALUE, backend="duckduckgo", max_results=5)
    assert factory.call_args.kwargs["timeout"] == 10
    assert factory.call_args.kwargs["verify"] is not False
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == SOURCE_UUID
    assert source["to_ids"] is True
    assert source["comment"] == "original"
    annotation = result["results"]["Object"][0]
    assert {a["object_relation"]: a["value"] for a in annotation["Attribute"]} == {
        "ref": ROW["href"],
        "text": "A report\n\nAn example snippet.",
    }
    assert all(a["to_ids"] is False for a in annotation["Attribute"])
    assert annotation["ObjectReference"][0]["referenced_uuid"] == SOURCE_UUID
    assert annotation["ObjectReference"][0]["relationship_type"] == "related-to"
    template = json.loads(
        resources.files("pymisp").joinpath("data/misp-objects/objects/annotation/definition.json").read_text()
    )
    strict = MISPObject("annotation", strict=True, misp_objects_template_custom=template)
    strict.from_dict(**annotation)
    strict._validate()


@pytest.mark.parametrize("kind", module.mispattributes["input"])
def test_supported_inputs_are_searched_as_supplied(client, kind):
    assert "results" in module.handler(query(value="misp-project.org", kind=kind))
    client[1].text.assert_called_once_with("misp-project.org", backend="duckduckgo", max_results=5)


@pytest.mark.parametrize("config", [None, {}, {"max_results": "", "timeout": None}, {"max_results": "  "}])
def test_blank_settings_use_defaults(client, config):
    assert "results" in module.handler(query(config=config))
    assert client[0].call_args.kwargs["timeout"] == 10
    assert client[1].text.call_args.kwargs["max_results"] == 5


def test_custom_settings_limit_output_even_if_backend_returns_more(client):
    client[1].text.return_value = [ROW, dict(ROW, href="https://example.org/second")]
    result = module.handler(query(config={"max_results": "1", "timeout": "20"}))
    assert len(result["results"]["Object"]) == 1
    assert client[0].call_args.kwargs["timeout"] == 20
    assert client[1].text.call_args.kwargs["max_results"] == 1


@pytest.mark.parametrize("config", [[], "bad", False])
def test_invalid_config_never_contacts_search(client, config):
    assert "error" in module.handler(query(config=config))
    client[0].assert_not_called()


@pytest.mark.parametrize("setting", ["max_results", "timeout"])
@pytest.mark.parametrize("value", [0, -1, 999, "invalid", "1.5", 1.5, True, [], {}, "nan", "inf"])
def test_invalid_settings_never_contact_search(client, setting, value):
    assert "error" in module.handler(query(config={setting: value}))
    client[0].assert_not_called()


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {}}'])
def test_invalid_requests_never_contact_search(client, raw):
    assert "error" in module.handler(raw)
    client[0].assert_not_called()


@pytest.mark.parametrize("value", [None, 123, [], "", "  ", "x" * 2001])
def test_invalid_values_never_contact_search(client, value):
    assert "error" in module.handler(query(value=value))
    client[0].assert_not_called()


def test_invalid_uuid_or_unsupported_input_never_contacts_search(client):
    assert "error" in module.handler(query(attribute={"type": "url", "value": VALUE, "uuid": "bad"}))
    assert "error" in module.handler(query(kind="attachment"))
    client[0].assert_not_called()


def test_missing_dependency_returns_actionable_error():
    original_import = builtins.__import__

    def missing_ddgs(name, *args, **kwargs):
        if name == "ddgs":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=missing_ddgs):
        result = module.handler(query())
    assert "Install 'ddgs>=9.16.1,<10'" in result["error"]


@pytest.mark.parametrize("exception_name", ["DDGSException", "RatelimitException", "TimeoutException"])
def test_search_errors_do_not_leak_query_or_proxy_credentials(client, exception_name):
    import ddgs.exceptions

    client[1].text.side_effect = getattr(ddgs.exceptions, exception_name)("sensitive query and proxy password")
    result = module.handler(query())
    assert "error" in result
    assert "sensitive" not in result["error"]
    assert "password" not in result["error"]
    assert client[1].text.call_count == 1


def test_empty_results_preserve_source(client):
    client[1].text.return_value = []
    result = module.handler(query())
    assert result["results"]["Object"] == []
    assert result["results"]["Attribute"][0]["uuid"] == SOURCE_UUID


def test_invalid_results_and_duplicates_are_skipped(client):
    client[1].text.return_value = [
        None,
        ROW,
        ROW,
        {"href": "javascript:alert(1)"},
        {"href": "https://example.org:bad/"},
    ]
    result = module.handler(query())
    assert len(result["results"]["Object"]) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "//duckduckgo.com/l/",
        "https://duckduckgo.com/l/",
        "http://www.duckduckgo.com/l",
        "https://html.duckduckgo.com/l/",
    ],
)
def test_redirect_wrappers_return_decoded_destination(client, prefix):
    destination = "https://example.org/é/report?next=%2Fpath%3Fx%3D1&label=a+b#section"
    client[1].text.return_value = [dict(ROW, href=prefix + "?uddg=" + quote(destination, safe="") + "&rut=tracking")]
    result = module.handler(query())
    annotation = result["results"]["Object"][0]
    assert {a["object_relation"]: a["value"] for a in annotation["Attribute"]} == {
        "ref": destination,
        "text": "A report\n\nAn example snippet.",
    }


def test_protocol_relative_destination_uses_https(client):
    client[1].text.return_value = [dict(ROW, href="//example.org/report")]
    result = module.handler(query())
    annotation = result["results"]["Object"][0]
    assert next(a["value"] for a in annotation["Attribute"] if a["object_relation"] == "ref") == ROW["href"]


def test_wrapped_and_direct_results_are_deduplicated(client):
    client[1].text.return_value = [
        dict(ROW, href="//duckduckgo.com/l/?uddg=" + quote(ROW["href"], safe="")),
        ROW,
    ]
    assert len(module.handler(query())["results"]["Object"]) == 1


@pytest.mark.parametrize(
    "destination",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https:///missing-host",
        "https://example.org:bad/",
        "https://user:pass@example.org/",
        "https://example.org/\npath",
        "https://example.org/\x00path",
    ],
)
def test_wrapped_invalid_destinations_are_skipped(client, destination):
    client[1].text.return_value = [dict(ROW, href="//duckduckgo.com/l/?uddg=" + quote(destination, safe=""))]
    result = module.handler(query())
    assert result["results"]["Object"] == []
    assert result["results"]["Attribute"][0]["uuid"] == SOURCE_UUID


@pytest.mark.parametrize(
    "query_string", ["", "rut=tracking", "uddg=", "uddg=https%3A%2F%2Fexample.org&uddg=https%3A%2F%2Fother.example"]
)
def test_incomplete_or_ambiguous_wrappers_are_skipped(client, query_string):
    client[1].text.return_value = [dict(ROW, href="//duckduckgo.com/l/?" + query_string)]
    assert module.handler(query())["results"]["Object"] == []


def test_other_sites_with_uddg_parameters_are_preserved(client):
    url = "https://duckduckgo.com.example.org/l/?uddg=https%3A%2F%2Fother.example"
    client[1].text.return_value = [dict(ROW, href=url)]
    annotation = module.handler(query())["results"]["Object"][0]
    assert next(a["value"] for a in annotation["Attribute"] if a["object_relation"] == "ref") == url


def test_link_only_result(client):
    client[1].text.return_value = [{"href": ROW["href"]}]
    result = module.handler(query())
    annotation = result["results"]["Object"][0]
    assert next(a["value"] for a in annotation["Attribute"] if a["object_relation"] == "text") == ROW["href"]


@pytest.mark.parametrize("rows", [None, {}, "bad"])
def test_invalid_response_shape(client, rows):
    client[1].text.return_value = rows
    assert "invalid search response" in module.handler(query())["error"]


def test_proxy_and_ca_configuration_are_respected(client):
    with patch.dict("os.environ", {"DDGS_PROXY": "http://proxy:8080", "SSL_CERT_FILE": "/etc/test-ca.pem"}):
        assert "results" in module.handler(query())
    client[0].assert_called_once_with(proxy="http://proxy:8080", timeout=10, verify="/etc/test-ca.pem")


def test_module_discovery_contract():
    assert module.handler() is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]
