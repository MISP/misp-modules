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
