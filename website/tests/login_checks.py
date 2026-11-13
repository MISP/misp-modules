"""Post-login redirect checks using the real login form, CSRF and session."""

import os
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from preview_server import create_fixture_app


class LoginRedirectTests(unittest.TestCase):
    base_url = "https://misp.example"
    password = "login-redirect-test-admin"

    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-login-")
        cls.addClassCleanup(cls.directory.cleanup)
        with patch.dict(
            os.environ, {"SESSION_SQLALCHEMY_TABLE": "login_test_sessions"}
        ):
            cls.app = create_fixture_app(Path(cls.directory.name) / "login.sqlite")

    def setUp(self):
        from app.utils import utils

        password = patch.object(utils, "ADMIN_PASSWORD", self.password)
        password.start()
        self.addCleanup(password.stop)

    def login(self, target=None, password=None, remember=False):
        from app import db
        from app.models import User

        # Each subtest performs an independent administrator login.
        with self.app.app_context():
            User.query.delete()
            db.session.commit()
        self.client = self.app.test_client()
        page = self.client.get("/login", base_url=self.base_url)
        token = re.search(
            rb'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', page.data
        )[1].decode()
        data = {
            "password": self.password if password is None else password,
            "csrf_token": token,
        }
        if remember:
            data["remember_me"] = "y"
        return self.client.post(
            "/login",
            base_url=self.base_url,
            query_string={} if target is None else {"next": target},
            headers={"Referer": self.base_url + "/login"},
            data=data,
        )

    def test_external_target_is_rejected_after_successful_login(self):
        response = self.login("https://evil.example/phish")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")
        self.assertEqual(
            self.client.get("/add_external_tool", base_url=self.base_url).status_code,
            200,
        )

    def test_unsafe_or_malformed_targets_fall_back_to_home(self):
        for target in (
            "http://evil.example/phish",
            "//evil.example/phish",
            "///evil.example/phish",
            "////evil.example/phish",
            r"/\evil.example/phish",
            r"\evil.example/phish",
            r"\\evil.example/phish",
            r"https:\\evil.example/phish",
            " \t//evil.example/phish",
            "/\t/evil.example/phish",
            "/\r\n/evil.example/phish",
            "/\x00/evil.example/phish",
            "/\x7f/evil.example/phish",
            "https:///evil.example/phish",
            "https://[invalid",
            "//[invalid",
            "https://misp.example\uff0fevil.example",
            "https://misp.example@evil.example/phish",
            "https://user@misp.example/history",
            "https://misp.example.evil.example/phish",
            "https://misp.example:8443/history",
            "https://misp.example//evil.example/phish",
            "javascript:alert(1)",
            "data:text/html,example",
            "https:evil.example/phish",
            "ftp://misp.example/history",
        ):
            with self.subTest(target=target):
                response = self.login(target)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, "/")

    def test_local_targets_preserve_path_query_and_fragment(self):
        for target, expected in (
            (None, "/"),
            ("", "/"),
            ("/", "/"),
            ("/external_tools?view=active#tools", "/external_tools?view=active#tools"),
            ("external_tools?view=active", "/external_tools?view=active"),
            ("?view=active", "/?view=active"),
            ("#tools", "/#tools"),
            ("https://misp.example/history?q=domain#last", "/history?q=domain#last"),
            ("http://misp.example/history", "/history"),
            ("//misp.example/history", "/history"),
            ("https://MISP.EXAMPLE/history", "/history"),
            (
                "/history?next=https://evil.example",
                "/history?next=https://evil.example",
            ),
            ("/caf\u00e9", "/caf%C3%A9"),
            ("/%2f%2fevil.example", "/%2f%2fevil.example"),
        ):
            with self.subTest(target=target):
                response = self.login(target)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, expected)
                self.assertFalse(urlsplit(response.location).netloc)
                self.assertFalse(urlsplit(response.location).scheme)

    def test_protected_page_login_round_trip(self):
        client = self.app.test_client()
        protected = client.get("/add_external_tool", base_url=self.base_url)
        self.assertEqual(protected.status_code, 302)
        next_url = parse_qs(urlsplit(protected.location).query)["next"][0]
        response = self.login(next_url)
        self.assertEqual(response.location, "/add_external_tool")
        self.assertEqual(
            self.client.get(response.location, base_url=self.base_url).status_code,
            200,
        )

    def test_same_host_with_port_is_converted_to_a_local_path(self):
        self.base_url = "https://misp.example:8443"
        response = self.login("https://misp.example:8443/history?q=domain")
        self.assertEqual(response.location, "/history?q=domain")

    def test_wrong_password_does_not_redirect_or_authenticate(self):
        response = self.login("https://evil.example/phish", password="incorrect")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)
        with self.client.session_transaction(base_url=self.base_url) as session:
            self.assertNotIn("_user_id", session)

    def test_login_still_requires_csrf(self):
        client = self.app.test_client()
        response = client.post(
            "/login?next=https://evil.example/phish",
            base_url=self.base_url,
            data={"password": self.password},
        )
        self.assertEqual(response.status_code, 400)

    def test_remember_me_is_preserved(self):
        response = self.login("https://evil.example/phish", remember=True)
        self.assertEqual(response.location, "/")
        self.assertTrue(
            any(
                cookie.startswith("remember_token=")
                for cookie in response.headers.getlist("Set-Cookie")
            )
        )
