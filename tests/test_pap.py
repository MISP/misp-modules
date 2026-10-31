from types import SimpleNamespace
from unittest.mock import Mock, patch

import orjson
import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.pap import has_pap_red, pap_red_error


@pytest.mark.parametrize("tags", [["PAP:RED"], [{"name": "PAP:RED"}], [{"Tag": {"name": "PAP:RED"}}], [" pap:red "]])
@pytest.mark.parametrize("key", ["tags", "Tag", "AttributeTag", "ObjectTag", "EventTag"])
def test_tag_formats(key, tags):
    assert has_pap_red({key: tags})


@pytest.mark.parametrize(
    "payload",
    [
        {"attribute": {"Tag": [{"name": "PAP:RED"}]}},
        {"Attribute": {"AttributeTag": [{"Tag": {"name": "PAP:RED"}}]}},
        {"object": {"Tag": [{"name": "PAP:RED"}]}},
        {"Object": {"Attribute": [{"Tag": [{"name": "PAP:RED"}]}]}},
        {"event": {"EventTag": [{"Tag": {"name": "PAP:RED"}}]}},
        {"Event": {"Object": [{"Attribute": [{"Tag": [{"name": "PAP:RED"}]}]}]}},
        {"attribute": {"Object": {"Event": {"Tag": [{"name": "PAP:RED"}]}}}},
        {"tags": ["PAP:GREEN"], "Event": {"Tag": [{"name": "PAP:RED"}]}},
    ],
)
def test_supplied_parent_and_nested_markings(payload):
    assert has_pap_red(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"tags": ["PAP:AMBER", "PAP:GREEN", "TLP:RED", "PAP:RED-extra"]},
        {"tags": [None, {}, 1, {"name": None}, {"name": [None]}]},
        {"attribute": None, "Object": "PAP:RED", "Event": 5, "Tag": False},
        {"domain": "PAP:RED", "attribute": {"value": "PAP:RED", "comment": "PAP:RED"}},
        {"config": {"tags": ["PAP:RED"], "Event": {"Tag": [{"name": "PAP:RED"}]}}},
        {"tags": [{"name": "TLP:RED", "description": "PAP:RED"}]},
    ],
)
def test_unrelated_values_and_malformed_context_are_not_markings(payload):
    assert not has_pap_red(payload)


@pytest.mark.parametrize("metadata", [{}, None, {"data-source": "external"}, {"data-source": "INTERNAL"}])
def test_only_explicit_internal_module_metadata_allows_manual_expansion(metadata):
    module = SimpleNamespace(version=lambda: metadata)
    assert pap_red_error(module, {"tags": ["PAP:RED"], "config": {"data-source": "internal"}})
    assert pap_red_error(SimpleNamespace(), {"tags": ["PAP:RED"]})
    assert pap_red_error(SimpleNamespace(version=lambda: {"data-source": "internal"}), {"tags": ["PAP:RED"]}) is None


class TestPapPolicyEndpoint(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        self.handlers = {}
        for name, source, module_types, legacy, category in (
            ("external", "external", ["expansion", "hover"], False, "expansion"),
            ("legacy", None, ["expansion", "hover"], True, "expansion"),
            ("internal", "internal", ["expansion", "hover"], False, "expansion"),
            ("internal-legacy", "internal", ["expansion"], True, "expansion"),
            ("hover-only", "internal", ["hover"], False, "expansion"),
            ("import", "external", ["import"], False, "import_mod"),
            ("export", "external", ["export"], False, "export_mod"),
            ("action", "external", ["action"], False, "action_mod"),
        ):
            metadata = {"module-type": module_types}
            if source:
                metadata["data-source"] = source
            self.handlers[name] = SimpleNamespace(
                **{"handler" if legacy else "dict_handler": Mock(return_value={"results": []})},
                version=Mock(return_value=metadata),
                introspection=lambda: {"input": ["domain"]},
            )
            self.handlers[f"type:{name}"] = category
        self.config = Mock()
        self.config.resolve.side_effect = lambda name, payload: payload
        for attribute, value in (
            ("MODULES_HANDLERS", self.handlers),
            ("MODULE_CONFIG", self.config),
            ("MODULE_STATISTICS", server.ModuleStatistics()),
            ("RESTRICT_PAP_RED", True),
            ("OPENAPI_DOCUMENT", server.openapi_builder.build_document(self.handlers, "localhost", 6666)),
        ):
            patcher = patch.object(server, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        cache = patch.object(server.ListModules, "CACHE", None)
        cache.start()
        self.addCleanup(cache.stop)
        for name, module in self.handlers.items():
            if not name.startswith("type:"):
                module.version.reset_mock()

    def get_app(self):
        return Application([(r"/query", server.QueryModule), (r"/modules", server.ListModules)])

    def query(self, name, **context):
        response = self.fetch("/query", method="POST", body=orjson.dumps({"module": name, **context}))
        assert response.code == 200
        return orjson.loads(response.body)

    def test_disabled_policy_preserves_legacy_bytes_and_skips_metadata(self):
        with patch.object(server, "RESTRICT_PAP_RED", False):
            body = b'{ "module": "legacy", "tags": ["PAP:RED"], "hover": true }'
            response = self.fetch("/query", method="POST", body=body)
            assert orjson.loads(response.body) == {"results": []}
            self.handlers["legacy"].handler.assert_called_once_with(q=body)
            self.handlers["legacy"].version.assert_not_called()
            assert self.query("external", tags=["PAP:RED"], hover=True) == {"results": []}
            self.handlers["external"].version.assert_not_called()

    def test_red_is_blocked_before_configuration_or_either_handler(self):
        for name in ("external", "legacy"):
            for context in (
                {"tags": ["PAP:RED"]},
                {"attribute": {"Tag": [{"name": "PAP:RED"}]}},
                {"object": {"Tag": [{"name": "PAP:RED"}]}},
                {"Event": {"EventTag": [{"Tag": {"name": "PAP:RED"}}]}},
                {"tags": ["PAP:RED"], "hover": True},
                {"tags": ["PAP:RED"], "data-source": "internal", "config": {"restrict_pap_red": False}},
            ):
                assert "PAP:RED" in self.query(name, **context)["error"]
            module = self.handlers[name]
            getattr(module, "handler" if name == "legacy" else "dict_handler").assert_not_called()
            stats = server.MODULE_STATISTICS.snapshot({name: "expansion"})["modules"][name]
            assert stats["module_errors"] == stats["queries"] == 6
            assert stats["successes"] == 0
        self.config.resolve.assert_not_called()

    def test_internal_manual_allowed_and_hover_blocked(self):
        for name in ("internal", "internal-legacy"):
            assert self.query(name, tags=["PAP:RED"]) == {"results": []}
            handler = getattr(self.handlers[name], "handler" if name.endswith("legacy") else "dict_handler")
            handler.assert_called_once()
            handler.reset_mock()
            assert "Hover" in self.query(name, tags=["PAP:RED"], hover=True)["error"]
            handler.assert_not_called()
        assert "Hover" in self.query("hover-only", tags=["PAP:RED"])["error"]
        self.handlers["hover-only"].dict_handler.assert_not_called()

    def test_other_tags_untagged_requests_and_other_module_families_unchanged(self):
        for name in ("external", "legacy", "internal", "hover-only"):
            for context in ({}, {"tags": []}, {"tags": ["PAP:AMBER", "TLP:RED"]}):
                assert self.query(name, **context) == {"results": []}
            self.handlers[name].version.assert_not_called()
        for name in ("import", "export", "action"):
            assert self.query(name, tags=["PAP:RED"], hover=True) == {"results": []}
            self.handlers[name].version.assert_not_called()

    def test_metadata_is_discoverable_without_request_override(self):
        response = self.fetch("/modules")
        modules = {module["name"]: module for module in orjson.loads(response.body)}
        assert modules["internal"]["meta"]["data-source"] == "internal"
        assert modules["external"]["meta"]["data-source"] == "external"
        examples = server.OPENAPI_DOCUMENT["paths"]["/modules"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["examples"]["modules"]["value"]
        assert {module["name"]: module for module in examples} == modules


@pytest.mark.parametrize("enabled", [True, False])
def test_global_cli_option(monkeypatch, enabled):
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test"] + (["--restrict-pap-red"] if enabled else []))
    monkeypatch.setattr(server, "RESTRICT_PAP_RED", not enabled)
    monkeypatch.setattr(server.signal, "signal", Mock())
    monkeypatch.setattr(server, "warn_if_degraded", Mock())
    monkeypatch.setattr(server, "init_logger", Mock())
    monkeypatch.setattr(server.misp_modules, "promote_lib_to_root", Mock())
    monkeypatch.setattr(server.misp_modules, "iterate_modules", Mock(return_value=[]))
    monkeypatch.setattr(server, "OPENAPI_DOCUMENT", {})
    monkeypatch.setattr(server, "MODULE_CONFIG", server.ModuleConfig())
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", Mock())
    assert server.main() == 0
    assert server.RESTRICT_PAP_RED is enabled
