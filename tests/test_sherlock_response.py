import json
import sys
import tempfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from tornado import gen
from tornado.concurrent import Future
from tornado.httpclient import HTTPClientError, HTTPRequest
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.cache import ModuleCache
from misp_modules.module_config import ModuleConfig
from misp_modules.modules.expansion import sherlock
from misp_modules.statistics import ModuleStatistics

UUID = "3850286d-e887-5ab4-beae-1c33095b60d0"


class TestSherlockResponse(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(prefix="test-sherlock-response-")
        self.addCleanup(directory.cleanup)
        self.executable = Path(directory.name) / "sherlock"
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "import csv, pathlib, sys\n"
            "directory = pathlib.Path(sys.argv[sys.argv.index('--folderoutput') + 1])\n"
            "username = sys.argv[-1]\n"
            "with (directory / (username + '.csv')).open('w', newline='') as report:\n"
            "    writer = csv.writer(report)\n"
            "    writer.writerow(['username', 'name', 'url_user', 'exists'])\n"
            "    for i in range(177):\n"
            "        writer.writerow([username, f'Site {i}', f'https://example.org/{i}/{username}', 'Claimed'])\n"
            "    for i in range(34):\n"
            "        writer.writerow([username, f'Failed {i}', '', 'Unknown' if i < 17 else 'WAF'])\n",
            encoding="utf-8",
        )
        self.executable.chmod(0o700)
        for name, value in (
            ("MODULES_HANDLERS", {"sherlock": sherlock, "type:sherlock": "expansion"}),
            ("MODULE_CACHE", ModuleCache()),
            ("MODULE_CONFIG", ModuleConfig()),
            ("MODULE_STATISTICS", ModuleStatistics()),
        ):
            patcher = patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def get_app(self):
        return Application([(r"/query", server.QueryModule)])

    def query(self, timeout=30):
        return json.dumps(
            {
                "module": "sherlock",
                "timeout": timeout,
                "config": {"sherlock_path": str(self.executable)},
                "attribute": {"type": "text", "value": "chess", "uuid": UUID},
            }
        )

    def test_all_177_accounts_reach_the_http_client(self):
        if sys.platform == "win32":
            self.skipTest("Fixture executable uses a POSIX shebang")
        with self.assertLogs("misp-modules", level="DEBUG") as logs:
            response = self.fetch("/query", method="POST", body=self.query())
        assert response.code == 200
        assert response.headers["Content-Type"] == "application/json"
        assert int(response.headers["Content-Length"]) == len(response.body)
        result = json.loads(response.body)["results"]
        assert len(result["Attribute"]) == 1
        assert result["Attribute"][0]["uuid"] == UUID
        objects = result["Object"]
        assert len(objects) == len({obj["uuid"] for obj in objects}) == 177
        accounts = set()
        for obj in objects:
            assert obj["name"] == "user-account"
            assert "34 site lookups failed or were blocked" in obj["comment"]
            assert obj["ObjectReference"][0]["referenced_uuid"] == UUID
            assert obj["ObjectReference"][0]["relationship_type"] == "related-to"
            assert len(obj["Attribute"]) == 3
            assert all(attribute["to_ids"] is False for attribute in obj["Attribute"])
            values = {attribute["object_relation"]: attribute["value"] for attribute in obj["Attribute"]}
            assert values["username"] == "chess"
            accounts.add((values["account-type"], values["link"]))
        assert accounts == {(f"Site {i}", f"https://example.org/{i}/chess") for i in range(177)}
        text = "\n".join(logs.output)
        assert "MISP response ready with 177 user-account objects" in text
        assert f"response prepared: {len(response.body)} bytes" in text
        assert f"response flushed: {len(response.body)} bytes (outcome=successes" in text

    @gen_test
    async def test_request_timeout_reports_that_late_accounts_cannot_be_delivered(self):
        entered = Future()
        release = Event()
        workers = []
        original_run_request = server.QueryModule.run_request

        def lookup(*args):
            self.io_loop.add_callback(entered.set_result, True)
            if not release.wait(3):
                raise RuntimeError("Test did not release the lookup")
            return [("GitHub", "https://github.com/chess")], 0

        def run_request(handler, *args):
            future = original_run_request(handler, *args)
            workers.append(future)
            return future

        with (
            self.assertLogs("misp-modules", level="DEBUG") as logs,
            patch.object(sherlock, "_lookup", side_effect=lookup),
            patch.object(server.QueryModule, "run_request", run_request),
        ):
            try:
                request = self.http_client.fetch(
                    HTTPRequest(self.get_url("/query"), method="POST", body=self.query(timeout=1))
                )
                await entered
                response = await request
            finally:
                release.set()
            late_response, outcome = await workers[0]
        assert json.loads(response.body) == {"error": "Timeout."}
        assert response.headers["Content-Type"] == "application/json"
        assert len(json.loads(late_response)["results"]["Object"]) == 1
        assert outcome == "successes"
        text = "\n".join(logs.output)
        assert "outcome=timeouts" in text
        assert "response prepared after request timeout" in text
        assert "result cannot be delivered to this request" in text

    @gen_test
    async def test_client_disconnect_is_logged_and_late_response_is_not_reported_as_flushed(self):
        worker = Future()
        entered = Future()
        disconnected = Future()
        completed = Future()
        original_close = server.QueryModule.on_connection_close
        original_warning = server.LOGGER.warning

        def run_request(handler, *args):
            entered.set_result(True)
            return worker

        def on_close(handler):
            original_close(handler)
            disconnected.set_result(True)

        def warning(message, *args):
            original_warning(message, *args)
            if "response" in message and ("not delivered" in message or "completed after" in message):
                if not completed.done():
                    completed.set_result(True)

        with (
            self.assertLogs("misp-modules", level="DEBUG") as logs,
            patch.object(server.QueryModule, "run_request", run_request),
            patch.object(server.QueryModule, "on_connection_close", on_close),
            patch.object(server.LOGGER, "warning", side_effect=warning),
        ):
            request = self.http_client.fetch(
                HTTPRequest(self.get_url("/query"), method="POST", body=self.query(), request_timeout=0.1)
            )
            await entered
            with self.assertRaises(HTTPClientError) as caught:
                await request
            assert caught.exception.code == 599
            await gen.with_timeout(self.io_loop.time() + 2, disconnected)
            worker.set_result((b'{"results":{"Object":[]}}', "successes"))
            await gen.with_timeout(self.io_loop.time() + 2, completed)
        text = "\n".join(logs.output)
        assert "client disconnected before response" in text
        assert "response flushed" not in text
