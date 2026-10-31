from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock, patch

import orjson
import pytest
from tornado import gen
from tornado.concurrent import Future
from tornado.httpclient import HTTPRequest
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules import openapi, statistics


def test_statistics_aggregation(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(statistics.time, "perf_counter", lambda: clock[0])
    collector = statistics.ModuleStatistics()
    types = {"used": "expansion", "unused": "import_mod"}
    initial = collector.snapshot(types)
    assert initial["uptime_seconds"] == 0
    unused = initial["modules"]["unused"]
    assert unused["queries"] == unused["in_flight"] == unused["errors"] == 0
    assert unused["success_rate"] is unused["last_query_at"] is None
    assert unused["response_time_seconds"]["average"] is None

    for duration, outcome in enumerate(("successes", "module_errors", "exceptions", "timeouts"), start=1):
        started = collector.start("used", 10)
        pending = collector.snapshot(types)["modules"]["used"]
        assert pending["in_flight"] == 1
        assert pending["queries"] == duration
        clock[0] += duration
        collector.finish("used", started, outcome, 20)

    snapshot = collector.snapshot(types)
    totals = snapshot["totals"]
    assert snapshot["uptime_seconds"] == 10
    assert totals["queries"] == totals["completed"] == 4
    assert totals["in_flight"] == 0
    assert totals["successes"] == totals["module_errors"] == totals["exceptions"] == totals["timeouts"] == 1
    assert totals["errors"] == 3
    assert totals["success_rate"] == 0.25
    assert totals["error_rate"] == 0.75
    assert totals["request_bytes"] == 40
    assert totals["response_bytes"] == 80
    timing = totals["response_time_seconds"]
    assert {key: timing[key] for key in ("count", "total", "min", "max", "average", "last")} == {
        "count": 4,
        "total": 10,
        "min": 1,
        "max": 4,
        "average": 2.5,
        "last": 4,
    }
    assert timing["buckets"]["0.5"] == 0
    assert timing["buckets"]["1"] == 1
    assert timing["buckets"]["5"] == timing["buckets"]["+Inf"] == 4
    assert snapshot["modules"]["used"] == {"type": "expansion", **totals}
    assert initial["modules"]["used"]["queries"] == 0
    # Snapshots do not expose mutable collector state.
    timing["buckets"]["1"] = 99
    assert collector.snapshot(types)["totals"]["response_time_seconds"]["buckets"]["1"] == 1
    assert statistics.ModuleStatistics().snapshot(types)["totals"]["queries"] == 0


def test_thread_safe_collection():
    collector = statistics.ModuleStatistics()

    def query(index):
        name = "one" if index % 2 else "two"
        started = collector.start(name, 5)
        collector.finish(name, started, "successes", 10)
        snapshot = collector.snapshot({"one": "expansion", "two": "export_mod"})
        assert snapshot["totals"]["queries"] == sum(module["queries"] for module in snapshot["modules"].values())
        assert snapshot["totals"]["completed"] == sum(module["completed"] for module in snapshot["modules"].values())

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(query, range(200)))
    totals = collector.snapshot({})["totals"]
    assert totals["queries"] == totals["successes"] == 200
    assert totals["request_bytes"] == 1000
    assert totals["response_bytes"] == 2000
    assert totals["in_flight"] == 0


class TestStatisticsEndpoint(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        self.handlers = {}
        for attribute, value in (
            ("MODULES_HANDLERS", self.handlers),
            ("MODULE_STATISTICS", statistics.ModuleStatistics()),
        ):
            patcher = patch.object(server, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.add_module("unused", lambda **kwargs: {})

    def get_app(self):
        return Application([(r"/query", server.QueryModule), (r"/statistics", server.Statistics)])

    def add_module(self, name, handler, legacy=False):
        self.handlers[name] = SimpleNamespace(**{"handler" if legacy else "dict_handler": handler})
        self.handlers[f"type:{name}"] = "expansion"

    def snapshot(self):
        response = self.fetch("/statistics")
        assert response.code == 200
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["Cache-Control"] == "no-store"
        return orjson.loads(response.body)

    def test_empty_and_repeated_reads(self):
        first = self.snapshot()
        second = self.snapshot()
        assert first["modules"] == second["modules"]
        assert first["totals"] == second["totals"]
        assert first["totals"]["queries"] == 0
        assert list(first["modules"]) == ["unused"]
        assert first["modules"]["unused"]["type"] == "expansion"
        assert second["uptime_seconds"] >= first["uptime_seconds"] >= 0
        assert first["started_at"].endswith("+00:00")

    def test_success_errors_and_legacy_handler(self):
        results = [
            ({"results": []}, "successes"),
            ({"error": "service failure", "results": []}, "module_errors"),
            ({"errors": ["service failure"]}, "module_errors"),
            ({"error": "", "errors": []}, "successes"),
            (None, "successes"),
            ([{"value": "example"}], "successes"),
        ]
        request_bytes = response_bytes = 0
        for index, (result, outcome) in enumerate(results):
            name = f"module-{index}"
            self.add_module(name, lambda result=result, **kwargs: result, legacy=index % 2 == 0)
            body = orjson.dumps({"module": name, "config": {"apikey": "sensitive-key"}})
            response = self.fetch("/query", method="POST", body=body)
            assert response.code == 200
            assert orjson.loads(response.body) == result
            module = self.snapshot()["modules"][name]
            assert module["queries"] == module["completed"] == module[outcome] == 1
            assert module["errors"] == (outcome == "module_errors")
            assert module["in_flight"] == 0
            assert module["request_bytes"] == len(body)
            assert module["response_bytes"] == len(response.body)
            request_bytes += len(body)
            response_bytes += len(response.body)

        snapshot = self.snapshot()
        assert snapshot["totals"]["queries"] == len(results)
        assert snapshot["totals"]["successes"] == 4
        assert snapshot["totals"]["module_errors"] == 2
        assert snapshot["totals"]["request_bytes"] == request_bytes
        assert snapshot["totals"]["response_bytes"] == response_bytes
        encoded = orjson.dumps(snapshot)
        assert b"sensitive-key" not in encoded
        assert b"service failure" not in encoded

    def test_exceptions_and_serialization_failures(self):
        def failing(**kwargs):
            raise RuntimeError("sensitive exception")

        for name, handler in (("raises", failing), ("unserializable", lambda **kwargs: {"value": 1 << 100})):
            self.add_module(name, handler)
            response = self.fetch("/query", method="POST", body=orjson.dumps({"module": name}))
            assert response.code == 200
            assert orjson.loads(response.body) == {"error": "Something went wrong, look in the server logs for details"}
            module = self.snapshot()["modules"][name]
            assert module["exceptions"] == module["errors"] == module["completed"] == 1
            assert module["successes"] == module["in_flight"] == 0
            assert module["response_bytes"] == len(response.body)

    def test_invalid_requests_do_not_create_module_entries(self):
        for body in (
            b"not json",
            b"null",
            b"[]",
            b"{}",
            b'{"module":"missing"}',
            b'{"module":"unused","timeout":"invalid"}',
            b'{"module":"type:unused"}',
        ):
            self.fetch("/query", method="POST", body=body)
        snapshot = self.snapshot()
        assert snapshot["totals"]["queries"] == 0
        assert list(snapshot["modules"]) == ["unused"]

    @gen_test
    async def test_in_flight_then_timeout_and_late_completion(self):
        worker = Future()
        entered = Future()

        def run_request(*args):
            entered.set_result(True)
            return worker

        with patch.object(server.QueryModule, "run_request", run_request):
            request = self.http_client.fetch(
                HTTPRequest(
                    self.get_url("/query"), method="POST", body=orjson.dumps({"module": "unused", "timeout": 1})
                )
            )
            await entered
            pending_response = await self.http_client.fetch(self.get_url("/statistics"))
            pending = orjson.loads(pending_response.body)["modules"]["unused"]
            assert pending["in_flight"] == pending["queries"] == 1
            assert pending["completed"] == 0
            response = await request
            assert orjson.loads(response.body) == {"error": "Timeout."}
            before = server.MODULE_STATISTICS.snapshot({"unused": "expansion"})
            module = before["modules"]["unused"]
            assert module["timeouts"] == module["errors"] == module["completed"] == 1
            assert module["queries"] == 1
            assert module["in_flight"] == module["successes"] == 0
            assert module["response_time_seconds"]["last"] >= 1
            worker.set_result((b'{"results": []}', "successes"))
            await gen.sleep(0)
            after = server.MODULE_STATISTICS.snapshot({"unused": "expansion"})
            assert after["modules"] == before["modules"]
            assert after["totals"] == before["totals"]

    @gen_test
    async def test_concurrent_queries(self):
        self.add_module("custom", lambda **kwargs: {"results": []})
        requests = [
            self.http_client.fetch(
                HTTPRequest(self.get_url("/query"), method="POST", body=orjson.dumps({"module": name}))
            )
            for name in ["custom", "unused"] * 10
        ]
        responses = await gen.multi(requests)
        assert all(response.code == 200 for response in responses)
        snapshot = server.MODULE_STATISTICS.snapshot({"custom": "expansion", "unused": "expansion"})
        assert snapshot["totals"]["queries"] == snapshot["totals"]["successes"] == 20
        for module in snapshot["modules"].values():
            assert module["queries"] == module["successes"] == 10
            assert module["in_flight"] == 0


def test_statistics_route_registered(monkeypatch):
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test"])
    monkeypatch.setattr(server.signal, "signal", Mock())
    monkeypatch.setattr(server, "warn_if_degraded", Mock())
    monkeypatch.setattr(server, "init_logger", Mock())
    monkeypatch.setattr(server.misp_modules, "promote_lib_to_root", Mock())
    monkeypatch.setattr(server.misp_modules, "iterate_modules", Mock(return_value=[]))
    monkeypatch.setattr(server, "OPENAPI_DOCUMENT", {})
    httpserver = Mock()
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", httpserver)
    assert server.main() == 0
    application = httpserver.call_args.args[0]
    assert any(rule.target is server.Statistics for rule in application.wildcard_router.rules)


def test_openapi_statistics_contract():
    document = openapi.build_document({}, "localhost", 6666)
    schema = document["paths"]["/statistics"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["$ref"] == "#/components/schemas/StatisticsResponse"
    # Validate the actual snapshot against the published schema, including nulls for unused modules.
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(document["components"]["schemas"]["StatisticsResponse"])
    jsonschema.validate(
        statistics.ModuleStatistics().snapshot({"unused": "import_mod"}),
        {"$ref": schema["$ref"], "components": document["components"]},
    )
