import logging
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import orjson
import pytest
from tornado import gen
from tornado.httpclient import HTTPRequest
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.module_config import ModuleConfig, ModuleConfigError


def write_config(path, modules):
    path.write_bytes(orjson.dumps({"version": 1, "modules": modules}))
    return ModuleConfig.from_file(str(path))


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        {"version": 1},
        {"version": 1, "modules": {}, "unexpected": "secret"},
        {"version": True, "modules": {}},
        {"version": 2, "modules": {}},
        {"version": "1", "modules": {}},
        {"version": 1, "modules": []},
        {"version": 1, "modules": {"": {"config": {}}}},
        {"version": 1, "modules": {"type:example": {"config": {}}}},
        *(
            {"version": 1, "modules": {"example": settings}}
            for settings in (
                None,
                [],
                {},
                {"config": {"apikey": "secret"}, "typo": True},
                {"config": None},
                {"config": []},
                {"config": {"": "secret"}},
                {"config": {}, "fallback_when_empty": "apikey"},
                {"config": {}, "fallback_when_empty": ["apikey"]},
                {"config": {}, "fallback_when_empty": [[]]},
            )
        ),
    ],
)
def test_invalid_schema_is_rejected_without_values(tmp_path, document):
    path = tmp_path / "modules.json"
    path.write_bytes(orjson.dumps(document))
    with pytest.raises(ModuleConfigError) as caught:
        ModuleConfig.from_file(str(path))
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("contents", [b'{"apikey": "secret",', b"\xffsecret", b"NaN"])
def test_invalid_json_is_rejected_without_values(tmp_path, contents):
    path = tmp_path / "modules.json"
    path.write_bytes(contents)
    with pytest.raises(ModuleConfigError, match="must contain valid JSON"):
        ModuleConfig.from_file(str(path))


def test_unreadable_file(tmp_path):
    for path in (tmp_path / "missing.json", tmp_path):
        with pytest.raises(ModuleConfigError, match="Unable to read"):
            ModuleConfig.from_file(str(path))


@pytest.mark.parametrize("value", [None, "", False, 0, " ", "api-key", [], {}])
@pytest.mark.parametrize("fallback_when_empty", [[], ["apikey"]])
def test_api_precedence_and_explicit_empty_policy(tmp_path, value, fallback_when_empty):
    config = write_config(
        tmp_path / "modules.json",
        {
            "example": {
                "config": {"apikey": "local-key", "url": "https://local.example"},
                "fallback_when_empty": fallback_when_empty,
            }
        },
    )
    payload = {"module": "example", "config": {"apikey": value, "other": "api-only"}, "timeout": 42}
    before = deepcopy(payload)
    resolved = config.resolve("example", payload)
    expected = "local-key" if fallback_when_empty and (value is None or value == "") else value
    assert resolved == {
        "module": "example",
        "config": {"apikey": expected, "url": "https://local.example", "other": "api-only"},
        "timeout": 42,
    }
    assert payload == before


def test_missing_config_load_once_and_module_isolation(tmp_path):
    path = tmp_path / "modules.json"
    config = write_config(path, {"one": {"config": {"apikey": "one-key"}}, "two": {"config": {"apikey": "two-key"}}})
    path.unlink()
    for name in ("one", "two"):
        for payload in ({"module": name}, {"module": name, "config": {}}):
            assert config.resolve(name, payload)["config"] == {"apikey": f"{name}-key"}
    unknown = {"module": "unknown"}
    assert config.resolve("unknown", unknown) is unknown


@pytest.mark.parametrize("value", [None, [], "", False, "invalid"])
def test_malformed_api_config_is_left_to_existing_handler(tmp_path, value):
    config = write_config(tmp_path / "modules.json", {"example": {"config": {"apikey": "local-key"}}})
    payload = {"module": "example", "config": value}
    assert config.resolve("example", payload) is payload


def test_nested_defaults_and_api_values_are_isolated_between_threads(tmp_path):
    config = write_config(tmp_path / "modules.json", {"example": {"config": {"nested": {"values": []}}}})
    payload = {"module": "example", "config": {"api_nested": {"values": []}}}

    def query(index):
        resolved = config.resolve("example", payload)
        resolved["config"]["nested"]["values"].append(index)
        resolved["config"]["api_nested"]["values"].append(index)
        return resolved

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(query, range(100)))
    assert payload["config"]["api_nested"]["values"] == []
    for index, result in enumerate(results):
        assert result["config"]["nested"]["values"] == [index]
        assert result["config"]["api_nested"]["values"] == [index]


class TestModuleConfigEndpoint(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        config = write_config(
            Path(temporary.name) / "modules.json",
            {
                name: {
                    "config": {"apikey": "server-local-secret", "url": "https://local.example"},
                    "fallback_when_empty": ["apikey"],
                }
                for name in ("modern", "legacy", "failure")
            },
        )
        self.modern = Mock(side_effect=lambda request: {"results": request})
        self.legacy = Mock(side_effect=lambda q: {"results": orjson.loads(q)})
        self.failure = Mock(return_value={"error": "Invalid API key"})
        self.handlers = {
            "modern": SimpleNamespace(dict_handler=self.modern),
            "legacy": SimpleNamespace(handler=self.legacy),
            "failure": SimpleNamespace(dict_handler=self.failure),
        }
        for name, module in list(self.handlers.items()):
            module.introspection = lambda: {"input": ["domain"]}
            module.version = lambda: {"config": ["apikey", "url"], "module-type": ["expansion"]}
            self.handlers[f"type:{name}"] = "expansion"
        for attribute, value in (
            ("MODULE_CONFIG", config),
            ("MODULES_HANDLERS", self.handlers),
            ("MODULE_STATISTICS", server.ModuleStatistics()),
            ("OPENAPI_DOCUMENT", server.openapi_builder.build_document(self.handlers, "localhost", 6666)),
        ):
            patcher = patch.object(server, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def get_app(self):
        return Application(
            [
                (r"/query", server.QueryModule),
                (r"/modules", server.ListModules),
                (r"/openapi.json", server.OpenAPISpec),
                (r"/statistics", server.Statistics),
            ]
        )

    def test_both_handler_styles_and_api_overrides(self):
        for name in ("modern", "legacy"):
            payload = {"module": name, "config": {"apikey": "", "url": "https://api.example"}, "domain": "example.org"}
            response = self.fetch("/query", method="POST", body=orjson.dumps(payload))
            assert response.code == 200
            received = orjson.loads(response.body)["results"]
            assert received == {**payload, "config": {"apikey": "server-local-secret", "url": "https://api.example"}}
            response = self.fetch("/query", method="POST", body=orjson.dumps({"module": name}))
            assert orjson.loads(response.body)["results"]["config"] == {
                "apikey": "server-local-secret",
                "url": "https://local.example",
            }

    def test_no_changes_preserves_legacy_json_bytes(self):
        body = b'{ "module": "legacy", "config": {"apikey": "api-key", "url": "api-url"} }'
        self.fetch("/query", method="POST", body=body)
        self.legacy.assert_called_once_with(q=body)
        self.legacy.reset_mock()
        with patch.object(server, "MODULE_CONFIG", ModuleConfig()):
            body = b'{ "module": "legacy" }'
            self.fetch("/query", method="POST", body=body)
            self.legacy.assert_called_once_with(q=body)
            response = self.fetch("/query", method="POST", body=b'{"module":"modern"}')
            assert "config" not in orjson.loads(response.body)["results"]

    def test_api_authentication_failure_is_not_retried(self):
        response = self.fetch("/query", method="POST", body=b'{"module":"failure","config":{"apikey":"bad-key"}}')
        assert orjson.loads(response.body) == {"error": "Invalid API key"}
        self.failure.assert_called_once()
        assert self.failure.call_args.kwargs["request"]["config"]["apikey"] == "bad-key"

    def test_debug_log_and_discovery_do_not_expose_local_defaults(self):
        with self.assertLogs(server.LOGGER, level=logging.DEBUG) as logs:
            self.fetch("/query", method="POST", body=b'{"module":"modern"}')
        assert "server-local-secret" not in "\n".join(logs.output)
        for endpoint in ("/modules", "/openapi.json", "/statistics"):
            response = self.fetch(endpoint)
            assert response.code == 200
            assert b"server-local-secret" not in response.body
            assert b"https://local.example" not in response.body

    @gen_test
    async def test_concurrent_requests_do_not_share_overrides(self):
        async def query(index):
            payload = {"module": "modern", "config": {"url": f"https://api-{index}.example"}}
            response = await self.http_client.fetch(
                HTTPRequest(self.get_url("/query"), method="POST", body=orjson.dumps(payload))
            )
            return orjson.loads(response.body)["results"]["config"]

        results = await gen.multi([query(index) for index in range(20)])
        assert results == [
            {"apikey": "server-local-secret", "url": f"https://api-{index}.example"} for index in range(20)
        ]


@pytest.fixture
def startup(monkeypatch):
    for attribute in ("init_logger", "warn_if_degraded"):
        monkeypatch.setattr(server, attribute, Mock())
    monkeypatch.setattr(server.signal, "signal", Mock())
    monkeypatch.setattr(server.misp_modules, "promote_lib_to_root", Mock())
    monkeypatch.setattr(server.misp_modules, "iterate_modules", Mock(return_value=[]))
    monkeypatch.setattr(server.openapi_builder, "build_document", Mock(return_value={}))
    monkeypatch.setattr(server, "OPENAPI_DOCUMENT", {})
    monkeypatch.setattr(server, "MODULE_CONFIG", ModuleConfig())
    httpserver = Mock()
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", httpserver)
    return httpserver


def test_startup_loads_only_explicit_file(tmp_path, monkeypatch, startup):
    path = tmp_path / "modules.json"
    write_config(path, {"custom": {"config": {"apikey": "server-local-secret"}}})
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test", "--module-config", str(path)])
    assert server.main() == 0
    assert server.MODULE_CONFIG.resolve("custom", {}) == {"config": {"apikey": "server-local-secret"}}
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test"])
    with patch.object(ModuleConfig, "from_file") as load:
        assert server.main() == 0
        load.assert_not_called()
    payload = {"module": "custom"}
    assert server.MODULE_CONFIG.resolve("custom", payload) is payload


def test_bad_file_stops_startup_before_listening(tmp_path, monkeypatch, startup, capsys):
    path = tmp_path / "modules.json"
    path.write_text('{"version": 1, "modules": "server-local-secret"}')
    monkeypatch.setattr("sys.argv", ["misp-modules", "--module-config", str(path)])
    with pytest.raises(SystemExit) as caught:
        server.main()
    assert caught.value.code == 2
    startup.assert_not_called()
    server.misp_modules.iterate_modules.assert_not_called()
    error = capsys.readouterr().err
    assert "must be an object" in error
    assert "server-local-secret" not in error
