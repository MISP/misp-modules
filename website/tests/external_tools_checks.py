"""External-tool security and persistence regression checks."""

import os
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from preview_server import create_fixture_app


class ExternalToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-external-tools-")
        with patch.dict(
            os.environ, {"SESSION_SQLALCHEMY_TABLE": "external_tool_test_sessions"}
        ):
            cls.app = create_fixture_app(Path(cls.directory.name) / "tools.sqlite")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        from app import db
        from app.models import ExternalTools, User
        from app.utils import utils

        self.password = patch.object(
            utils, "ADMIN_PASSWORD", "external-tool-test-admin"
        )
        self.password.start()
        self.addCleanup(self.password.stop)
        with self.app.app_context():
            ExternalTools.query.delete()
            User.query.delete()
            tool = ExternalTools(
                name="Saved tool",
                url="https://example.org/ingest",
                api_key="saved-secret",
                is_active=True,
            )
            db.session.add(tool)
            db.session.commit()
            self.tool_id = tool.id
        self.client = self.app.test_client()
        page = self.client.get("/external_tools")
        self.token = re.search(
            rb'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', page.data
        )[1].decode()
        self.config = {
            "tool_id": self.tool_id,
            "tool_name": "Updated tool",
            "tool_url": "https://example.org/updated",
        }

    def login(self):
        response = self.client.post(
            "/login",
            data={
                "password": "external-tool-test-admin",
                "csrf_token": self.token,
            },
        )
        self.assertEqual(response.status_code, 302)

    def snapshot(self):
        from app.models import ExternalTools

        with self.app.app_context():
            return [
                (tool.id, tool.name, tool.url, tool.api_key, tool.is_active)
                for tool in ExternalTools.query.order_by(ExternalTools.id).all()
            ]

    def requests(self):
        return [
            (
                "/add_external_tool",
                {
                    "data": {
                        "name": "New tool",
                        "url": "https://example.org/new",
                        "api_key": "new-secret",
                    }
                },
            ),
            (f"/external_tools/{self.tool_id}/delete_tool", {}),
            (f"/external_tools/change_status?tool_id={self.tool_id}", {}),
            (
                "/external_tools/change_config",
                {
                    "json": {
                        "result_dict": {
                            **self.config,
                            "tool_api_key": "replacement-secret",
                        }
                    }
                },
            ),
        ]

    def test_anonymous_mutations_are_denied_even_with_valid_csrf(self):
        before = self.snapshot()
        for url, options in self.requests():
            with self.subTest(url=url):
                response = self.client.post(
                    url, headers={"X-CSRFToken": self.token}, **options
                )
                self.assertEqual(
                    response.status_code, 302 if url == "/add_external_tool" else 403
                )
                self.assertEqual(self.snapshot(), before)
        response = self.client.get("/add_external_tool")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login?next=", response.location)

    def test_authorization_precedes_json_validation(self):
        response = self.client.post(
            "/external_tools/change_config",
            json=None,
            headers={"X-CSRFToken": self.token},
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_can_add_toggle_update_and_delete(self):
        self.login()
        self.assertEqual(self.client.get("/add_external_tool").status_code, 200)
        for url, options in [
            self.requests()[0],
            self.requests()[2],
            self.requests()[3],
            self.requests()[1],
        ]:
            response = self.client.post(
                url, headers={"X-CSRFToken": self.token}, **options
            )
            self.assertEqual(
                response.status_code, 302 if url == "/add_external_tool" else 200
            )
            if "change_status" in url:
                self.assertFalse(self.snapshot()[0][-1])
            if "change_config" in url:
                self.assertEqual(
                    self.snapshot()[0][1:4],
                    (
                        "Updated tool",
                        "https://example.org/updated",
                        "replacement-secret",
                    ),
                )

    def test_site_without_admin_password_keeps_existing_access_policy(self):
        from app.utils import utils

        with patch.object(utils, "ADMIN_PASSWORD", None):
            self.assertEqual(self.client.get("/add_external_tool").status_code, 200)
            for url, options in [
                self.requests()[0],
                self.requests()[2],
                self.requests()[3],
                self.requests()[1],
            ]:
                response = self.client.post(
                    url, headers={"X-CSRFToken": self.token}, **options
                )
                self.assertEqual(
                    response.status_code, 302 if url == "/add_external_tool" else 200
                )

    def test_list_never_exposes_credentials(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                if authenticated:
                    self.login()
                response = self.client.get("/external_tools/list")
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(b"saved-secret", response.data)
                self.assertNotIn("api_key", response.json[0])
                self.assertEqual(response.json[0]["id"], self.tool_id)

    def test_missing_or_blank_key_preserves_saved_key(self):
        self.login()
        for extra in ({}, {"tool_api_key": ""}):
            with self.subTest(extra=extra):
                response = self.client.post(
                    "/external_tools/change_config",
                    json={"result_dict": {**self.config, **extra}},
                    headers={"X-CSRFToken": self.token},
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    self.snapshot()[0][1:4],
                    ("Updated tool", "https://example.org/updated", "saved-secret"),
                )

    def test_invalid_config_returns_bad_request_without_changes(self):
        self.login()
        before = self.snapshot()
        for body in (
            None,
            [],
            {},
            {"result_dict": None},
            {"result_dict": []},
            {"result_dict": {}},
            {"result_dict": {**self.config, "tool_api_key": ["invalid"]}},
            {"result_dict": {**self.config, "tool_api_key": "x" * 61}},
        ):
            with self.subTest(body=body):
                response = self.client.post(
                    "/external_tools/change_config",
                    json=body,
                    headers={"X-CSRFToken": self.token},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.snapshot(), before)

    def test_stored_key_remains_available_for_server_side_submission(self):
        from app import home_core
        from app.models import ExternalTools

        with self.app.app_context(), patch("app.home_core.requests.post") as post:
            post.return_value.status_code = 200
            tool = ExternalTools.query.get(self.tool_id)
            self.assertTrue(home_core.submit_external_tool({"example": "result"}, tool))
            self.assertEqual(
                post.call_args.kwargs["headers"]["X-API-KEY"], "saved-secret"
            )

    def test_get_cannot_mutate_even_for_an_admin(self):
        self.login()
        before = self.snapshot()
        for url, _ in self.requests()[1:]:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 405)
                self.assertEqual(self.snapshot(), before)

    def test_all_mutations_require_csrf_even_for_an_admin(self):
        self.login()
        before = self.snapshot()
        for url, options in self.requests():
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url, **options).status_code, 400)
                self.assertEqual(self.snapshot(), before)

    def test_delete_is_committed_without_an_http_session(self):
        from app import db
        from app.external_tools import external_tools_core
        from app.models import ExternalTools

        with self.app.app_context():
            self.assertTrue(external_tools_core.delete_tool(self.tool_id))
            db.session.remove()
            self.assertIsNone(db.session.get(ExternalTools, self.tool_id))
