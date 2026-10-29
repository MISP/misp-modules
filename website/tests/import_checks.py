"""Exercise real import routes, request encoding, workers, and persistence."""

import base64
import io
import json
import os
import re
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from preview_server import create_fixture_app


class ImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-import-")
        # Flask-Session creates a mapped table per app; use a distinct table
        # when browser checks have already built their fixture app.
        with patch.dict(
            os.environ, {"SESSION_SQLALCHEMY_TABLE": "import_test_sessions"}
        ):
            cls.app = create_fixture_app(Path(cls.directory.name) / "import.sqlite")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        page = self.client.get("/import")
        self.token = re.search(
            rb'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', page.data
        )[1].decode()

    def post(self, **data):
        return self.client.post(
            "/run_import", data=data, headers={"X-CSRFToken": self.token}
        )

    def finish(self, response):
        self.assertEqual(response.status_code, 201, response.get_json())
        sid = response.get_json()["id"]
        from app.session_class import sessions

        session = next(s for s in sessions if s.uuid == sid)
        for worker in session.threads:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertTrue(self.client.get("/status/" + sid).get_json()["stopped"])
        return sid

    def test_catalogue_separates_imports_from_enrichment(self):
        imports = self.client.get("/get_import_modules").get_json()
        expansions = self.client.get("/get_modules").get_json()
        self.assertEqual([m["name"] for m in imports], ["remote_import", "url_import"])
        self.assertNotIn("url_import", [m["name"] for m in expansions])
        from app.utils import utils

        self.assertNotIn("request_on_query", utils.MODULES[-1])

    def test_file_bytes_reach_daemon_and_result_is_saved_and_downloadable(self):
        contents = b"\x00\xffbinary\r\n"
        result = {
            "results": {"Attribute": [{"type": "url", "value": "https://example.org"}]}
        }
        with patch("app.session_class.query_post_query", return_value=result) as query:
            sid = self.finish(
                self.post(
                    module="url_import",
                    source="file",
                    file=(io.BytesIO(contents), "../../urls.txt"),
                )
            )
        payload = query.call_args.args[0]
        self.assertEqual(base64.b64decode(payload["data"]), contents)
        self.assertEqual(payload["filename"], "urls.txt")
        self.assertEqual(payload["config"], {"include_scheme": "1"})
        self.assertNotIn("attribute", payload)
        saved = self.client.get("/result/" + sid).get_json()
        self.assertEqual(saved, {"urls.txt": {"url_import": result}})
        download = self.client.get(f"/download/{sid}?module=url_import&query=urls.txt")
        self.assertEqual(download.get_json(), result)
        self.assertIn("attachment", download.headers["Content-Disposition"])
        page = self.client.get("/query/" + sid)
        self.assertIn(b"IMPORT RESULTS", page.data)
        self.assertNotIn(b">Run again</button>", page.data)
        from app import db
        from app.models import Session_db

        with self.app.app_context():
            saved_session = Session_db.query.filter_by(uuid=sid).one()
            self.assertNotIn(
                "data", json.loads(saved_session.config_module)["url_import"]
            )
            self.assertNotIn(
                base64.b64encode(contents).decode(), saved_session.query_enter
            )

    def test_paste_is_utf8_encoded_and_boolean_serialized(self):
        with patch(
            "app.session_class.query_post_query", return_value={"results": []}
        ) as query:
            self.finish(
                self.post(
                    module="url_import",
                    source="paste",
                    data="https://example.org/café",
                    config=json.dumps({"include_scheme": False}),
                )
            )
        payload = query.call_args.args[0]
        self.assertEqual(
            base64.b64decode(payload["data"]).decode(), "https://example.org/café"
        )
        self.assertEqual(payload["config"]["include_scheme"], "0")

    def test_config_only_merges_saved_settings_and_explicit_overrides(self):
        from app import db
        from app.models import Module_Config
        from app.home_core import get_module_by_name

        with self.app.app_context():
            module = get_module_by_name("remote_import")
            Module_Config.query.filter_by(module_id=module.id).one().value = (
                "saved-test-key"
            )
            db.session.commit()
        for extra, expected in [
            ({}, "saved-test-key"),
            ({"apikey": "override"}, "override"),
        ]:
            with (
                self.subTest(extra=extra),
                patch(
                    "app.session_class.query_post_query", return_value={"results": []}
                ) as query,
            ):
                self.finish(
                    self.post(
                        module="remote_import",
                        source="config",
                        config=json.dumps({"report_id": "12", **extra}),
                    )
                )
            payload = query.call_args.args[0]
            self.assertEqual(
                payload,
                {
                    "module": "remote_import",
                    "config": {"report_id": "12", "apikey": expected},
                },
            )

    def test_validation_and_disabled_modules_never_execute(self):
        cases = [
            {"module": "dns", "source": "paste", "data": "example.org"},
            {"module": "unknown"},
            {"module": "url_import", "source": "config"},
            {"module": "url_import", "source": "file"},
            {"module": "url_import", "source": "paste", "data": ""},
            {"module": "url_import", "source": "paste", "data": "x", "config": "[]"},
            {"module": "url_import", "source": "paste", "data": "x", "config": "{"},
            {
                "module": "url_import",
                "source": "paste",
                "data": "x",
                "config": '{"unexpected":"x"}',
            },
            {"module": "remote_import", "source": "config"},
            {
                "module": "remote_import",
                "source": "config",
                "config": '{"report_id":"abc"}',
            },
        ]
        with patch("app.session_class.query_post_query") as query:
            for data in cases:
                with self.subTest(data=data):
                    self.assertEqual(self.post(**data).status_code, 400)
            query.assert_not_called()
        from app import db
        from app.home_core import get_module_by_name

        with self.app.app_context():
            module = get_module_by_name("url_import")
            module.is_active = False
            db.session.commit()
            try:
                self.assertEqual(
                    self.post(
                        module="url_import", source="paste", data="x"
                    ).status_code,
                    400,
                )
            finally:
                module.is_active = True
                db.session.commit()

    def test_size_limit_and_csrf(self):
        self.assertEqual(
            self.client.post("/run_import", data={"module": "url_import"}).status_code,
            400,
        )
        with patch("app.import_core.MAX_IMPORT_SIZE", 10):
            self.assertEqual(
                self.post(
                    module="url_import",
                    source="file",
                    file=(io.BytesIO(b"x" * 11), "large.txt"),
                ).status_code,
                400,
            )
            self.assertEqual(
                self.post(
                    module="url_import", source="paste", data="x" * (1024 * 1024 + 11)
                ).status_code,
                413,
            )

    def test_running_import_is_not_saved_until_worker_finishes(self):
        entered, release = threading.Event(), threading.Event()

        def slow_query(payload):
            entered.set()
            release.wait(10)
            return {"error": "Fixture import failed"}

        with patch("app.session_class.query_post_query", side_effect=slow_query):
            response = self.post(module="url_import", source="paste", data="x")
            sid = response.get_json()["id"]
            self.assertTrue(entered.wait(5))
            try:
                status = self.client.get("/status/" + sid).get_json()
                self.assertEqual(status["remaining"], 1)
                self.assertEqual(status["registered"], 0)
                self.assertFalse(status["stopped"])
            finally:
                release.set()
            self.finish(response)
        status = self.client.get("/status/" + sid).get_json()
        self.assertEqual(status["nb_errors"], 1)

    def test_daemon_failure_finishes_with_a_visible_error(self):
        for failure in (
            {"message": "Module service unavailable"},
            ValueError("Invalid module response"),
        ):
            with self.subTest(failure=failure):
                kwargs = (
                    {"side_effect": failure}
                    if isinstance(failure, Exception)
                    else {"return_value": failure}
                )
                with patch("app.session_class.query_post_query", **kwargs):
                    sid = self.finish(
                        self.post(module="url_import", source="paste", data="x")
                    )
                self.assertEqual(
                    self.client.get("/status/" + sid).get_json()["nb_errors"], 1
                )
                result = self.client.get("/result/" + sid).get_json()
                self.assertIn("error", result["Pasted data"]["url_import"])


if __name__ == "__main__":
    unittest.main()
