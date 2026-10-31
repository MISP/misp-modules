"""Export input compatibility, worker persistence, downloads, and feed boundaries."""

import base64
import importlib.util
import io
import json
import os
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from preview_server import create_fixture_app

UUID = "55b7c901-614c-44d1-a638-440e950d210b"
EVENT = {"Event": {"info": "An OSINT event", "uuid": UUID, "Attribute": [
    {"type": "domain", "category": "Network activity", "value": "example.org"}
]}}


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-export-")
        with patch.dict(os.environ, {"SESSION_SQLALCHEMY_TABLE": "export_test_sessions"}):
            cls.app = create_fixture_app(Path(cls.directory.name) / "export.sqlite")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        page = self.client.get("/export")
        self.token = re.search(rb'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', page.data)[1].decode()

    def post(self, data=EVENT, **extra):
        body = {"module": "file_export", "source": "file",
                "file": (io.BytesIO(json.dumps(data).encode()), "../../event.json"), **extra}
        return self.client.post("/run_export", data=body, headers={"X-CSRFToken": self.token})

    def finish(self, response):
        self.assertEqual(response.status_code, 201, response.get_json())
        sid = response.get_json()["id"]
        from app.session_class import sessions
        session = next(s for s in sessions if s.uuid == sid)
        for worker in session.threads:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertTrue(self.client.get("/status/" + sid).get_json()["stopped"])
        self.assertIsNone(session.export_payload)
        return sid

    def test_catalogue_upload_normalization_and_saved_download(self):
        self.assertEqual([m["name"] for m in self.client.get("/get_export_modules").json], ["file_export"])
        self.assertNotIn("file_export", [m["name"] for m in self.client.get("/get_modules").json])
        content = "café <script>alert(1)</script>\n".encode()
        for data in (EVENT, EVENT["Event"], [EVENT], {"response": [EVENT]},
                     {"Event": {"info": "Legacy"}, "Attribute": EVENT["Event"]["Attribute"]}):
            with self.subTest(data=data), patch("app.session_class.query_post_query", return_value={"data": base64.b64encode(content).decode()}) as query:
                sid = self.finish(self.post(data))
                sent = query.call_args.args[0]
                self.assertEqual(sent["data"][0]["Attribute"], sent["data"][0]["Event"]["Attribute"])
                self.assertEqual(sent["config"]["include_context"], "1")
                result = self.client.get("/result/" + sid).json["event.json"]["file_export"]
                self.assertEqual(result["export"]["preview"], content.decode())
                download = self.client.get(f"/download/{sid}?module=file_export&query=event.json&format=export")
                self.assertEqual(download.data, content)
                self.assertEqual(download.mimetype, "application/octet-stream")
                self.assertIn("event.txt", download.headers["Content-Disposition"])
                page = self.client.get("/query/" + sid)
                self.assertIn(b"EXPORT RESULTS", page.data)
                self.assertNotIn(b">Run again</button>", page.data)
                from app.models import Session_db
                with self.app.app_context():
                    saved = Session_db.query.filter_by(uuid=sid).one()
                    self.assertEqual(json.loads(saved.config_module), {})
                    self.assertNotIn("example.org", saved.query_enter)

    def test_real_legacy_and_modern_exporters_accept_normalized_events(self):
        from app.export_core import normalize_events
        root = Path(__file__).resolve().parents[2]
        for name in ("liteexport", "cef_export"):
            spec = importlib.util.spec_from_file_location(name, root / f"misp_modules/modules/export_mod/{name}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            result = module.handler(json.dumps({"data": normalize_events(EVENT), "config": {"indent_json_export": None}}))
            self.assertNotIn("error", result)
            self.assertIn(b"example.org", base64.b64decode(result["data"]))

    def test_invalid_input_and_disabled_module_do_not_start(self):
        for data in ({}, [], {"Event": None}, {"Event": {"info": "x", "Object": {}}}, {"response": [False]}, {"Event": {"info": "x", "Object": [{"Attribute": False}]}}):
            with self.subTest(data=data), patch("app.session_class.Session_class.start") as start:
                self.assertEqual(self.post(data).status_code, 400)
                start.assert_not_called()
        self.assertEqual(self.post(module="url_import").status_code, 400)
        self.assertEqual(self.post(config='{"unknown": "x"}').status_code, 400)
        self.assertEqual(self.post(config='[]').status_code, 400)
        self.assertEqual(self.post(file=(io.BytesIO(b"invalid"), "bad.json")).status_code, 400)
        self.assertEqual(self.post(file=(io.BytesIO(b"\xff"), "bad.json")).status_code, 400)
        self.assertEqual(self.post(file=(io.BytesIO(b""), "")).status_code, 400)
        from app import db
        from app.home_core import get_module_by_name
        with self.app.app_context():
            module = get_module_by_name("file_export")
            module.is_active = False
            db.session.commit()
        try:
            self.assertEqual(self.post().status_code, 400)
        finally:
            with self.app.app_context():
                get_module_by_name("file_export").is_active = True
                db.session.commit()

    def test_collection_capabilities_config_and_limits(self):
        from preview_server import EXPORT_MODULE
        with patch.dict(EXPORT_MODULE["mispattributes"], {"inputSource": ["event"]}):
            self.assertEqual(self.post([EVENT, EVENT]).status_code, 400)
        with patch("app.export_core.MAX_EXPORT_SIZE", 10):
            self.assertEqual(self.post().status_code, 400)
        self.assertEqual(self.client.post("/run_export", data={}).status_code, 400)
        self.assertEqual(self.post(file=(io.BytesIO(b"x" * (21 * 1024 * 1024 + 1)), "large.json")).status_code, 413)
        from app import db
        from app.home_core import get_module_by_name, get_module_config_module
        with self.app.app_context():
            get_module_config_module(get_module_by_name("file_export").id)[0].value = "saved"
            db.session.commit()
        for config, expected in (({}, "saved"), ({"prefix": "override", "include_context": False}, "override")):
            with patch("app.session_class.query_post_query", return_value={"data": ""}) as query:
                self.finish(self.post(config=json.dumps(config)))
                self.assertEqual(query.call_args.args[0]["config"]["prefix"], expected)

    def test_binary_empty_invalid_output_and_daemon_errors(self):
        from app.export_core import prepare_export_result
        pdf = prepare_export_result({"data": base64.b64encode(b"%PDF ASCII data").decode()},
                                    {"responseType": "application/pdf", "outputFileExtension": "pdf"}, "event.json")
        self.assertIsNone(pdf["export"]["preview"])
        self.assertEqual(pdf["export"]["filename"], "event.pdf")
        for response, failed in (({"data": base64.b64encode(b"\xff\x00").decode()}, False), ({"data": ""}, False), ({"data": "!not-base64"}, True), ({"results": []}, True), ({"message": "Service unavailable"}, True), ({"error": "Failed"}, True)):
            with self.subTest(response=response), patch("app.session_class.query_post_query", return_value=response):
                sid = self.finish(self.post())
                self.assertEqual(self.client.get("/status/" + sid).json["nb_errors"], int(failed))
                result = self.client.get("/result/" + sid).json["event.json"]["file_export"]
                if failed:
                    self.assertIn("error", result)
                elif response["data"]:
                    self.assertIsNone(result["export"]["preview"])

    def test_body_limits_apply_before_csrf_and_respect_configuration(self):
        with patch("app.export_core.MAX_EXPORT_SIZE", 10):
            response = self.client.post("/run_export", data={
                "file": (io.BytesIO(b"x" * (1024 * 1024 + 11)), "large.json"),
            })
        self.assertEqual(response.status_code, 413)
        self.assertIn("20 MiB", response.json["message"])
        with patch.dict(self.app.config, {"MAX_CONTENT_LENGTH": 128}):
            self.assertEqual(self.post().status_code, 413)

    def test_feed_search_pagination_and_execution(self):
        manifest = {UUID: {"info": "Café OSINT", "date": "2026-10-29"}}
        manifest.update({f"00000000-0000-0000-0000-{i:012x}": {"info": "Older", "date": "2020-01-01"} for i in range(105)})
        with patch("app.export_core.get_manifest", return_value=manifest):
            first = self.client.get("/export_feed_events?feed=circl").json
            self.assertEqual(len(first["events"]), 100)
            self.assertEqual(first["events"][0]["uuid"], UUID)
            self.assertEqual(len(self.client.get("/export_feed_events?feed=circl&page=2").json["events"]), 6)
            self.assertEqual(self.client.get("/export_feed_events?feed=circl&search=caf%C3%A9").json["total"], 1)
            with patch("app.export_core.read_feed_json", return_value=EVENT) as read, patch("app.session_class.query_post_query", return_value={"data": ""}) as query:
                self.finish(self.post(source="feed", feed="circl", event=UUID))
                read.assert_called_once_with("circl", UUID + ".json")
                self.assertEqual(query.call_args.args[0]["data"][0]["Event"]["uuid"], UUID)

    def test_feed_errors_and_url_boundaries(self):
        from app.export_core import FeedError, read_feed_json
        for args in ("feed=http://localhost", "feed=circl&page=0", "feed=circl&page=bad"):
            self.assertEqual(self.client.get("/export_feed_events?" + args).status_code, 400)
        with patch("app.export_core.read_feed_json") as read:
            self.assertEqual(self.post(source="feed", feed="circl", event="../../secret").status_code, 400)
            read.assert_not_called()
        with patch("app.export_core.get_manifest", side_effect=FeedError("Feed unavailable")):
            self.assertEqual(self.client.get("/export_feed_events?feed=circl").status_code, 502)
            self.assertEqual(self.post(source="feed", feed="circl", event=UUID).status_code, 502)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 302
        with patch("app.export_core.requests.get", return_value=response) as get:
            with self.assertRaises(FeedError):
                read_feed_json("circl", "manifest.json")
            self.assertFalse(get.call_args.kwargs["allow_redirects"])
        response.status_code = 200
        response.iter_content.return_value = [b"not-json"]
        with patch("app.export_core.requests.get", return_value=response):
            with self.assertRaises(FeedError):
                read_feed_json("circl", "manifest.json")

    def login(self):
        response = self.client.post("/login", data={"password": "export-test-admin"},
                                    headers={"X-CSRFToken": self.token})
        self.assertEqual(response.status_code, 302)

    def test_export_authorization_covers_execution_live_and_saved_results(self):
        from app.utils import utils
        with patch.object(utils, "ADMIN_PASSWORD", "export-test-admin"):
            # Anonymous users can still obtain CSRF tokens; tokens do not grant access.
            self.assertEqual(self.client.get("/export").status_code, 302)
            with patch("app.session_class.Session_class.start") as start:
                self.assertEqual(self.post().status_code, 403)
                self.assertEqual(self.post(source="feed", feed="circl", event=UUID).status_code, 403)
                start.assert_not_called()
            for path in ("/get_export_modules", "/export_feeds", "/export_feed_events?feed=circl",
                         "/get_query_info/export-query", "/status/export-query", "/result/export-query",
                         "/download/export-query?module=file_export&query=event.json&format=export",
                         "/download/export-query?module=file_export&query=event.json",
                         "/download/export-query?module=file_export&query=event.json&format=csv"):
                with self.subTest(path=path):
                    self.assertEqual(self.client.get(path).status_code, 403)
            self.assertEqual(self.client.get("/query/export-query").status_code, 302)
            self.assertEqual(self.client.get("/result/test-query").status_code, 200)
            self.login()
            try:
                self.assertEqual(self.client.get("/export").status_code, 200)
                self.assertEqual(self.client.get("/get_export_modules").status_code, 200)
                with patch("app.session_class.query_post_query", return_value={"data": ""}):
                    response = self.post()
                    sid = response.json["id"]
                    # Before status finalizes persistence, access must also protect live results.
                    guest = self.app.test_client()
                    for path in ("/status/", "/result/", "/get_query_info/"):
                        self.assertEqual(guest.get(path + sid).status_code, 403)
                    self.finish(response)
                self.assertEqual(self.client.get("/result/" + sid).status_code, 200)
                self.client.get("/logout")
                self.assertEqual(self.client.get("/result/" + sid).status_code, 403)
                self.assertEqual(self.client.get(f"/download/{sid}?module=file_export&query=event.json&format=export").status_code, 403)
            finally:
                self.client.get("/logout")

    def test_firesight_uses_placeholders_instead_of_saved_credentials(self):
        from app import db
        from app.home_core import get_module_by_name, get_module_config_module, get_config
        from app.models import Session_db
        from app.utils import utils
        from app.utils.init_modules import create_modules_db
        from preview_server import MODULES

        name = "cisco_firesight_manager_ACL_rule_export"
        path = Path(__file__).resolve().parents[2] / f"misp_modules/modules/export_mod/{name}.py"
        spec = importlib.util.spec_from_file_location(name, path)
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        module = {"name": name, "meta": exporter.version(), "mispattributes": exporter.introspection()}
        saved_credentials = {"fmc_login": "shared-fmc-admin", "fmc_pass": "shared-fmc-password"}
        with patch.object(utils, "MODULES", [*MODULES, module]), patch.object(utils, "ADMIN_PASSWORD", "export-test-admin"):
            with self.app.app_context():
                create_modules_db()
                for setting in get_module_config_module(get_module_by_name(name).id):
                    setting.value = saved_credentials.get(get_config(setting.config_id).name, "fixture-setting")
                db.session.commit()
            self.assertEqual(self.post(module=name).status_code, 403)
            self.login()
            try:
                catalogue = self.client.get("/get_export_modules").json
                advertised = next(m for m in catalogue if m["name"] == name)
                self.assertEqual(set(advertised["credential_placeholders"]), set(saved_credentials))
                event = {"Event": {"id": "123", "info": "Fixture", "Attribute": []}}
                with patch("app.session_class.query_post_query", side_effect=lambda payload: exporter.handler(json.dumps(payload))) as query:
                    sid = self.finish(self.post(event, module=name))
                config = query.call_args.args[0]["config"]
                self.assertEqual(config["fmc_login"], "SET_FIRESIGHT_LOGIN")
                self.assertEqual(config["fmc_pass"], "SET_FIRESIGHT_PASSWORD")
                download = self.client.get(f"/download/{sid}?module={name}&query=event.json&format=export")
                self.assertEqual(download.status_code, 200)
                self.assertIn(b"SET_FIRESIGHT_LOGIN:SET_FIRESIGHT_PASSWORD", download.data)
                for secret in saved_credentials.values():
                    self.assertNotIn(secret.encode(), download.data)
                    self.assertNotIn(secret.encode(), self.client.get("/result/" + sid).data)
                self.assertEqual(self.post(event, module=name, config=json.dumps(saved_credentials)).status_code, 400)
                with self.app.app_context():
                    self.assertEqual(Session_db.query.filter_by(uuid=sid).one().config_module, "{}")
                self.assertEqual(self.client.get("/get_current_query_history").json["config"], {})
            finally:
                self.client.get("/logout")

    def test_export_settings_are_not_retained_in_session_or_saved_history(self):
        from app.models import Session_db
        secret = "run-only-api-credential"
        with patch("app.session_class.query_post_query", return_value={"data": ""}):
            sid = self.finish(self.post(config=json.dumps({"prefix": secret})))
        self.assertNotIn(secret.encode(), self.client.get("/get_history_session").data)
        self.assertEqual(self.client.get("/get_current_query_history").json["config"], {})
        with self.app.app_context():
            self.assertEqual(Session_db.query.filter_by(uuid=sid).one().config_module, "{}")

    def test_generic_module_endpoint_cannot_bypass_export_policy(self):
        # The preview fixture normally intercepts enrichment requests. Exercise
        # the real endpoint for this boundary test, preserving Flask's CSRF hook.
        hooks = [hook for hook in self.app.before_request_funcs[None] if hook.__name__ != "fixture_enrichment"]
        with patch.dict(self.app.before_request_funcs, {None: hooks}), patch("app.session_class.Session_class.start") as start:
            for input_type in ("export", "data", "domain"):
                response = self.client.post("/run_modules", json={
                    "query": ["event"], "input": input_type, "modules": ["file_export"],
                    "config": {}, "parent_id": "",
                }, headers={"X-CSRFToken": self.token})
                self.assertEqual(response.status_code, 400)
            start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
