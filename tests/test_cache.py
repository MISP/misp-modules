import threading
from concurrent.futures import Future, ThreadPoolExecutor
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
from misp_modules import cache
from misp_modules.module_config import ModuleConfig


def configured_cache(path, modules=None, **limits):
    if modules is None:
        modules = {"example": {"enabled": True, **limits}}
    path.write_bytes(orjson.dumps({"version": 1, "modules": modules}))
    return cache.ModuleCache.from_file(path)


def test_disabled_cache_does_not_hash_or_retain_requests(tmp_path):
    for engine in (
        cache.ModuleCache(),
        configured_cache(tmp_path / "cache.json", modules={"example": {}}),
        configured_cache(tmp_path / "cache.json", modules={"example": {"enabled": False}}),
    ):
        execute = Mock(return_value=(b"{}", "successes"))
        with patch.object(cache.hmac, "digest") as digest:
            for _ in range(2):
                assert engine.run("example", {}, execute) == (b"{}", "successes")
            digest.assert_not_called()
        assert execute.call_count == 2
        assert not engine.enabled_for("example")
        assert engine.snapshot({"example": "expansion"}) == {}


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        {"version": 1},
        {"version": True, "modules": {}},
        {"version": 2, "modules": {}},
        {"version": 1, "modules": []},
        {"version": 1, "modules": {}, "secret": "secret"},
        {"version": 1, "modules": {"": {}}},
        {"version": 1, "modules": {"type:example": {}}},
        *(
            {"version": 1, "modules": {"example": settings}}
            for settings in (
                None,
                [],
                {"typo": "secret"},
                {"enabled": "secret"},
                {"enabled": 1},
                {"ttl_seconds": 0},
                {"ttl_seconds": 0.1},
                {"max_entries": -1},
                {"max_entries": True},
                {"max_bytes": "secret"},
                {"max_bytes": None},
            )
        ),
    ],
)
def test_invalid_configuration_does_not_expose_values(tmp_path, document):
    path = tmp_path / "cache.json"
    path.write_bytes(orjson.dumps(document))
    with pytest.raises(cache.CacheConfigError) as caught:
        cache.ModuleCache.from_file(path)
    assert "secret" not in str(caught.value)


def test_unreadable_and_invalid_json(tmp_path):
    with pytest.raises(cache.CacheConfigError, match="Unable to read"):
        cache.ModuleCache.from_file(tmp_path / "missing")
    for body in (b"secret", b"\xffsecret", b'{"secret":'):
        path = tmp_path / "cache.json"
        path.write_bytes(body)
        with pytest.raises(cache.CacheConfigError, match="valid JSON"):
            cache.ModuleCache.from_file(path)


def test_key_matching_and_sensitive_context_isolation(tmp_path):
    engine = configured_cache(tmp_path / "cache.json", modules={name: {"enabled": True} for name in ("one", "two")})
    execute = Mock(return_value=(b'{"results":[]}', "successes"))
    payload = {
        "module": "one",
        "attribute": {"uuid": "first", "value": "example.org"},
        "config": {"apikey": "secret", "url": "https://one.example"},
    }
    engine.run("one", payload, execute)
    reordered = {
        "config": dict(reversed(list(payload["config"].items()))),
        "attribute": payload["attribute"],
        "module": "one",
    }
    engine.run("one", reordered, execute)
    assert execute.call_count == 1
    for change in (
        {"config": {**payload["config"], "apikey": "other-secret"}},
        {"config": {**payload["config"], "url": "https://two.example"}},
        {"attribute": {**payload["attribute"], "uuid": "second"}},
        {"attribute": {**payload["attribute"], "value": "different.org"}},
        {"event_id": 2},
        {"timeout": 10},
        {"options": [1, 2]},
        {"options": [2, 1]},
    ):
        engine.run("one", {**payload, **change}, execute)
    engine.run("two", {**payload, "module": "two"}, execute)
    assert execute.call_count == 10
    assert all(isinstance(key, bytes) and len(key) == 32 for key in engine._modules["one"].entries)
    snapshot = orjson.dumps(engine.snapshot({"one": "expansion", "two": "expansion"}))
    assert b"secret" not in snapshot and b"example.org" not in snapshot


def test_expiry_is_fixed_and_modules_have_independent_lru_limits(tmp_path, monkeypatch):
    clock = [100]
    monkeypatch.setattr(cache, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    engine = configured_cache(
        tmp_path / "cache.json",
        modules={name: {"enabled": True, "ttl_seconds": 10, "max_entries": 2} for name in ("one", "two")},
    )
    execute = Mock(return_value=(b"{}", "successes"))
    for name in ("one", "two"):
        engine.run(name, {"value": 1}, execute)
        engine.run(name, {"value": 2}, execute)
    engine.run("one", {"value": 1}, execute)  # Protect 1 as most recently used.
    engine.run("one", {"value": 3}, execute)  # Evict 2 only in module one.
    engine.run("two", {"value": 2}, execute)
    assert execute.call_count == 5
    clock[0] = 109
    engine.run("one", {"value": 1}, execute)
    assert execute.call_count == 5
    clock[0] = 110
    engine.run("one", {"value": 1}, execute)
    assert execute.call_count == 6  # The hit at 109 did not extend expiry.
    snapshot = engine.snapshot({"one": "expansion", "two": "expansion"})
    assert snapshot["one"]["evictions"] == 1
    assert snapshot["one"]["expired"] == snapshot["two"]["expired"] == 2
    assert snapshot["one"]["entries"] == 1
    assert snapshot["two"]["entries"] == 0


def test_response_byte_bound_and_oversized_results_do_not_flush_cache(tmp_path):
    engine = configured_cache(tmp_path / "cache.json", max_bytes=6)
    execute = Mock(return_value=(b"[12]", "successes"))
    engine.run("example", {"value": 1}, execute)
    engine.run("example", {"value": 2}, execute)
    oversized = Mock(return_value=(b"[123456]", "successes"))
    for _ in range(2):
        engine.run("example", {"value": 3}, oversized)
    engine.run("example", {"value": 2}, execute)
    assert execute.call_count == oversized.call_count == 2
    snapshot = engine.snapshot({"example": "expansion"})["example"]
    assert snapshot["entries"] == snapshot["evictions"] == 1
    assert snapshot["response_bytes"] == 4
    assert snapshot["skipped"] == 2


@pytest.mark.parametrize("result", [(b'{"error":"failure"}', "module_errors"), (b"null", "successes")])
def test_errors_and_null_are_not_retained(tmp_path, result):
    engine = configured_cache(tmp_path / "cache.json")
    execute = Mock(return_value=result)
    for _ in range(2):
        assert engine.run("example", {}, execute) == result
    assert execute.call_count == 2
    assert engine.snapshot({"example": "expansion"})["example"]["entries"] == 0


def test_deadline_and_empty_success(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "time", SimpleNamespace(monotonic=lambda: 20))
    engine = configured_cache(tmp_path / "cache.json")
    execute = Mock(return_value=(b'{"results":[]}', "successes"))
    engine.run("example", {}, execute, deadline=20)
    engine.run("example", {}, execute, deadline=21)
    engine.run("example", {}, execute, deadline=21)
    assert execute.call_count == 2
    snapshot = engine.snapshot({"example": "expansion"})["example"]
    assert snapshot["skipped"] == snapshot["stores"] == snapshot["hits"] == 1


@pytest.mark.parametrize("failure", [None, "module_errors", "exception"])
def test_concurrent_identical_queries_share_execution_and_cleanup(tmp_path, monkeypatch, failure):
    engine = configured_cache(tmp_path / "cache.json")
    entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
    counter_lock = threading.Lock()
    waiters = [0]

    class ObservedFuture(Future):
        def result(self, timeout=None):
            with counter_lock:
                waiters[0] += 1
                if waiters[0] == 7:
                    waiting.set()
            return super().result(timeout)

    monkeypatch.setattr(cache, "Future", ObservedFuture)

    def execute():
        entered.set()
        assert release.wait(5)
        if failure == "exception":
            raise RuntimeError("provider failed")
        return b"{}", failure or "successes"

    execute = Mock(side_effect=execute)
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(engine.run, "example", {}, execute)]
        try:
            assert entered.wait(5)
            futures.extend(executor.submit(engine.run, "example", {}, execute) for _ in range(7))
            assert waiting.wait(5)
            # Different keys can execute while the original key is blocked.
            other = Mock(return_value=(b"[]", "successes"))
            assert engine.run("example", {"different": True}, other) == (b"[]", "successes")
        finally:
            release.set()
        for future in futures:
            if failure == "exception":
                with pytest.raises(RuntimeError, match="provider failed"):
                    future.result(timeout=5)
            else:
                assert future.result(timeout=5) == (b"{}", failure or "successes")
    assert execute.call_count == 1
    snapshot = engine.snapshot({"example": "expansion"})["example"]
    assert snapshot["coalesced"] == 7
    assert snapshot["in_flight"] == 0
    retry = Mock(return_value=(b"{}", "successes"))
    engine.run("example", {}, retry)
    assert retry.call_count == int(failure is not None)


class TestCacheEndpoint(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "cache.json"
        self.cache = configured_cache(
            path, modules={name: {"enabled": True} for name in ("modern", "legacy", "error", "failure", "action")}
        )
        path.write_bytes(orjson.dumps({"version": 1, "modules": {"modern": {"config": {"apikey": "local-secret"}}}}))
        config = ModuleConfig.from_file(path)
        self.modern = Mock(return_value={"results": []})
        self.legacy = Mock(return_value={"results": []})
        self.error = Mock(return_value={"errors": ["provider error"]})
        self.failure = Mock(side_effect=RuntimeError("provider exception"))
        self.disabled = Mock(return_value={"results": []})
        self.action = Mock(return_value={"results": []})
        self.handlers = {
            "modern": SimpleNamespace(dict_handler=self.modern),
            "legacy": SimpleNamespace(handler=self.legacy),
            "error": SimpleNamespace(dict_handler=self.error),
            "failure": SimpleNamespace(dict_handler=self.failure),
            "disabled": SimpleNamespace(dict_handler=self.disabled),
            "action": SimpleNamespace(dict_handler=self.action),
        }
        for name in list(self.handlers):
            self.handlers[f"type:{name}"] = "action_mod" if name == "action" else "expansion"
        for attribute, value in (
            ("MODULE_CACHE", self.cache),
            ("MODULE_CONFIG", config),
            ("MODULES_HANDLERS", self.handlers),
            ("MODULE_STATISTICS", server.ModuleStatistics()),
        ):
            patcher = patch.object(server, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def get_app(self):
        return Application([(r"/query", server.QueryModule), (r"/statistics", server.Statistics)])

    def query(self, payload):
        return self.fetch("/query", method="POST", body=orjson.dumps(payload))

    def test_both_handlers_cache_and_legacy_body_is_preserved(self):
        body = b'{ "domain":"example.org", "module":"legacy" }'
        first = self.fetch("/query", method="POST", body=body)
        second = self.query({"module": "legacy", "domain": "example.org"})
        assert first.body == second.body
        self.legacy.assert_called_once_with(q=body)
        first = self.query({"module": "modern", "domain": "example.org"})
        second = self.query({"domain": "example.org", "module": "modern", "config": {"apikey": "local-secret"}})
        assert first.body == second.body
        self.modern.assert_called_once()
        assert self.modern.call_args.kwargs["request"]["config"]["apikey"] == "local-secret"
        self.query({"module": "modern", "domain": "example.org", "config": {"apikey": "different"}})
        assert self.modern.call_count == 2

    def test_failures_disabled_and_action_modules_are_executed_every_time(self):
        for name in ("error", "failure", "disabled", "action"):
            for _ in range(2):
                self.query({"module": name, "config": {"cache": {"enabled": True}}})
            assert getattr(self, name).call_count == 2

    def test_serialization_failures_are_not_cached(self):
        self.failure.side_effect = None
        self.failure.return_value = {"results": 1 << 100}
        for _ in range(2):
            response = self.query({"module": "failure"})
            assert orjson.loads(response.body) == {"error": "Something went wrong, look in the server logs for details"}
        assert self.failure.call_count == 2
        assert self.cache.snapshot({"failure": "expansion"})["failure"]["entries"] == 0

    def test_cached_body_is_isolated_from_mutable_module_results(self):
        self.modern.return_value = {"results": [{"values": ["original"]}]}
        first = self.query({"module": "modern"})
        self.modern.return_value["results"][0]["values"].append("changed")
        second = self.query({"module": "modern"})
        assert second.body == first.body == b'{"results":[{"values":["original"]}]}'
        self.modern.assert_called_once()

    def test_pap_policy_is_checked_before_serving_a_cached_result(self):
        payload = {"module": "modern", "tags": ["PAP:RED"]}
        with patch.object(server, "RESTRICT_PAP_RED", False):
            assert orjson.loads(self.query(payload).body) == {"results": []}
        with patch.object(server, "RESTRICT_PAP_RED", True):
            assert "PAP:RED" in orjson.loads(self.query(payload).body)["error"]
        self.modern.assert_called_once()
        assert self.cache.snapshot({"modern": "expansion"})["modern"]["hits"] == 0

    def test_statistics_preserve_query_counts_and_validate_schema(self):
        for _ in range(2):
            self.query({"module": "modern", "domain": "example.org"})
        response = self.fetch("/statistics")
        snapshot = orjson.loads(response.body)
        assert snapshot["modules"]["modern"]["queries"] == snapshot["modules"]["modern"]["successes"] == 2
        metrics = snapshot["cache"]["modules"]["modern"]
        assert metrics["misses"] == metrics["hits"] == metrics["saved_queries"] == metrics["entries"] == 1
        assert "disabled" not in snapshot["cache"]["modules"]
        assert "action" not in snapshot["cache"]["modules"]
        assert b"local-secret" not in response.body and b"example.org" not in response.body
        document = server.openapi_builder.build_document({}, "localhost", 6666)
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate(
            snapshot, {"$ref": "#/components/schemas/StatisticsResponse", "components": document["components"]}
        )
        with patch.object(server, "MODULE_CACHE", cache.ModuleCache()):
            assert "cache" not in orjson.loads(self.fetch("/statistics").body)

    @gen_test
    async def test_http_waiters_share_execution(self):
        entered, release = threading.Event(), threading.Event()

        def execute(request):
            entered.set()
            assert release.wait(5)
            return {"results": []}

        self.modern.side_effect = execute
        requests = [
            self.http_client.fetch(HTTPRequest(self.get_url("/query"), method="POST", body=b'{"module":"modern"}'))
            for _ in range(8)
        ]
        try:
            for _ in range(100):
                if self.cache.snapshot({"modern": "expansion"})["modern"]["coalesced"] == 7:
                    break
                await gen.sleep(0.01)
            assert entered.is_set()
            assert self.cache.snapshot({"modern": "expansion"})["modern"]["coalesced"] == 7
        finally:
            release.set()
        responses = await gen.multi(requests)
        assert all(response.body == b'{"results":[]}' for response in responses)
        self.modern.assert_called_once()

    @gen_test
    async def test_timed_out_worker_does_not_populate_cache(self):
        release, done = threading.Event(), threading.Event()

        def execute(request):
            assert release.wait(5)
            done.set()
            return {"results": []}

        self.modern.side_effect = execute
        try:
            response = await self.http_client.fetch(
                HTTPRequest(self.get_url("/query"), method="POST", body=b'{"module":"modern","timeout":1}')
            )
            assert orjson.loads(response.body) == {"error": "Timeout."}
        finally:
            release.set()
        for _ in range(100):
            if done.is_set() and self.cache.snapshot({"modern": "expansion"})["modern"]["in_flight"] == 0:
                break
            await gen.sleep(0.01)
        metrics = self.cache.snapshot({"modern": "expansion"})["modern"]
        assert metrics["entries"] == metrics["in_flight"] == 0
        assert metrics["skipped"] == 1


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
    monkeypatch.setattr(server, "MODULE_CACHE", cache.ModuleCache())
    monkeypatch.setattr(server, "MODULES_HANDLERS", {})
    httpserver = Mock()
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", httpserver)
    return httpserver


def test_startup_loads_cache_only_when_requested(tmp_path, monkeypatch, startup):
    path = tmp_path / "cache.json"
    configured_cache(path)
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test", "--cache-config", str(path)])
    assert server.main() == 0
    assert server.MODULE_CACHE.enabled_for("example")
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test"])
    with patch.object(cache.ModuleCache, "from_file") as load:
        assert server.main() == 0
        load.assert_not_called()
    assert not server.MODULE_CACHE.enabled_for("example")


@pytest.mark.parametrize("invalid", ["schema", "action_mod", "import_mod", "export_mod"])
def test_bad_configuration_stops_before_listening(tmp_path, monkeypatch, startup, capsys, invalid):
    path = tmp_path / "cache.json"
    configured_cache(path)
    if invalid == "schema":
        path.write_text('{"version":1,"modules":"secret"}')
    else:
        server.MODULES_HANDLERS.update({"example": SimpleNamespace(), "type:example": invalid})
    monkeypatch.setattr("sys.argv", ["misp-modules", "--cache-config", str(path)])
    with pytest.raises(SystemExit) as caught:
        server.main()
    assert caught.value.code == 2
    startup.assert_not_called()
    assert "secret" not in capsys.readouterr().err
