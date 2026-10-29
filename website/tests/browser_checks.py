"""Browser regression tests against real Flask templates and isolated fixture data.

Run: python -m unittest discover -s website/tests -p 'browser_checks.py' -v
Requires website dependencies, playwright, and Chromium (see doc/interface.md).
"""
import csv
import io
import json
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import WSGIRequestHandler, make_server

from preview_server import create_fixture_app


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


class InterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-modules-ui-")
        cls.app = create_fixture_app(Path(cls.directory.name) / "tests.sqlite")
        cls.server = make_server("127.0.0.1", 0, cls.app, threaded=True, request_handler=QuietHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.playwright = sync_playwright().start()
        options = {"args": ["--no-sandbox"]}
        if executable := os.environ.get("CHROMIUM_EXECUTABLE"):
            options["executable_path"] = executable
        cls.browser = cls.playwright.chromium.launch(**options)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.thread.join()
        cls.directory.cleanup()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 1000})
        self.page = self.context.new_page()
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.errors, [], "Unexpected browser JavaScript errors")

    def home(self):
        self.page.goto(self.base + "/")
        expect(self.page.get_by_role("combobox", name="MISP attribute")).to_be_enabled()

    def select_module(self, name):
        self.page.locator(".module-card").filter(has=self.page.locator(".module-name", has_text=name)).get_by_role("checkbox").check()

    def test_export_upload_preview_and_download(self):
        self.home()
        self.page.get_by_role("link", name="Export data", exact=True).click()
        self.page.get_by_label("Export module", exact=True).select_option("file_export")
        expect(self.page.get_by_label("include_context", exact=True)).to_be_checked()
        self.page.get_by_role("button", name="Run export", exact=True).click()
        expect(self.page.get_by_role("alert")).to_contain_text("Choose a MISP JSON file")
        self.page.get_by_label("MISP JSON file (up to 20 MiB)", exact=True).set_input_files({"name": "event.json", "mimeType": "application/json", "buffer": b'{"Event":{"info":"Example"}}'})
        self.page.get_by_label("Input source", exact=True).select_option("feed")
        self.page.get_by_label("Input source", exact=True).select_option("file")
        self.page.get_by_role("button", name="Run export", exact=True).click()
        expect(self.page.get_by_role("alert")).to_contain_text("Choose a MISP JSON file")
        self.page.get_by_label("MISP JSON file (up to 20 MiB)", exact=True).set_input_files({"name": "event.json", "mimeType": "application/json", "buffer": b'{"Event":{"info":"Example"}}'})
        self.page.route("**/run_export", lambda route: route.fulfill(status=201, content_type="application/json", body='{"id":"export-query"}'))
        with self.page.expect_request("**/run_export") as submitted:
            self.page.get_by_role("button", name="Run export", exact=True).click()
        self.assertIn('filename="event.json"', submitted.value.post_data)
        self.page.wait_for_url(self.base + "/query/export-query")
        expect(self.page.locator(".eyebrow").filter(has_text="EXPORT RESULTS")).to_be_visible()
        expect(self.page.locator("pre code")).to_contain_text("Exported <script>alert(1)</script> café")
        expect(self.page.locator("pre script")).to_have_count(0)
        expect(self.page.get_by_role("button", name="Run again", exact=True)).to_have_count(0)
        with self.page.expect_download() as downloaded:
            self.page.get_by_role("link", name="Download event.txt", exact=True).click()
        self.assertEqual(Path(downloaded.value.path()).read_bytes(), "Exported <script>alert(1)</script> café\n".encode())
        self.page.get_by_role("tab", name="JSON", exact=True).click()
        expect(self.page.locator("#result-panel")).to_contain_text("data")
        self.page.get_by_role("tab", name="Markdown", exact=True).click()
        expect(self.page.locator("pre code")).to_contain_text("Exported")

    def test_export_feed_selection_retry_and_payload(self):
        uuid = "55b7c901-614c-44d1-a638-440e950d210b"
        self.page.goto(self.base + "/export")
        self.page.get_by_label("Export module", exact=True).select_option("file_export")
        self.page.get_by_label("Input source", exact=True).select_option("feed")
        self.page.route("**/export_feed_events?**", lambda route: route.fulfill(status=502, content_type="application/json", body='{"message":"Feed temporarily unavailable"}'))
        self.page.get_by_label("OSINT feed", exact=True).select_option("circl")
        expect(self.page.get_by_role("alert")).to_contain_text("Feed temporarily unavailable")
        self.page.unroute("**/export_feed_events?**")
        self.page.route("**/export_feed_events?**", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"events": [{"uuid": uuid, "info": "OSINT sample", "date": "2026-10-29"}], "total": 1, "page": 1})))
        self.page.get_by_role("button", name="Try again", exact=True).click()
        self.page.get_by_label("MISP event", exact=True).select_option(uuid)
        self.page.set_viewport_size({"width": 320, "height": 800})
        self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"))
        self.page.get_by_role("checkbox", name="Override module settings").check()
        self.page.get_by_label("prefix", exact=True).fill("test prefix")
        self.page.route("**/run_export", lambda route: route.fulfill(status=201, content_type="application/json", body='{"id":"export-query"}'))
        with self.page.expect_request("**/run_export") as submitted:
            self.page.get_by_role("button", name="Run export", exact=True).click()
        self.assertIn(uuid, submitted.value.post_data)
        self.assertIn('name="feed"', submitted.value.post_data)
        self.assertIn("test prefix", submitted.value.post_data)
        self.page.wait_for_url(self.base + "/query/export-query")

    def test_export_access_requires_login_and_is_revoked_on_logout(self):
        from app.utils import utils
        utils.ADMIN_PASSWORD = "local-export-password"
        try:
            self.home()
            self.page.get_by_role("link", name="Export data", exact=True).click()
            self.page.wait_for_url("**/login?next=/export")
            self.page.get_by_label("Password", exact=True).fill("local-export-password")
            self.page.get_by_role("button", name="Log in", exact=True).click()
            self.page.wait_for_url(self.base + "/export")
            self.page.get_by_label("Export module", exact=True).select_option("file_export")
            self.page.goto(self.base + "/query/export-query")
            expect(self.page.get_by_role("link", name="Download event.txt", exact=True)).to_be_visible()
            self.page.get_by_role("link", name="Log out", exact=True).click()
            self.assertEqual(self.context.request.get(self.base + "/result/export-query").status, 403)
            self.page.goto(self.base + "/query/export-query")
            self.page.wait_for_url("**/login?next=/query/export-query")
        finally:
            utils.ADMIN_PASSWORD = None

    def test_export_embedded_credentials_have_placeholders_instead_of_inputs(self):
        self.page.route("**/get_export_modules", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps([{
                "name": "cisco_firesight_manager_ACL_rule_export",
                "meta": {"description": "FireSIGHT script export", "config": ["fmc_ip_addr", "fmc_login", "fmc_pass"]},
                "mispattributes": {}, "credential_placeholders": ["fmc_login", "fmc_pass"],
            }]),
        ))
        self.page.goto(self.base + "/export")
        self.page.get_by_label("Export module", exact=True).select_option("cisco_firesight_manager_ACL_rule_export")
        expect(self.page.get_by_text("The website replaces them with placeholders.", exact=False)).to_be_visible()
        self.page.get_by_role("checkbox", name="Override module settings").check()
        expect(self.page.get_by_label("fmc_ip_addr", exact=True)).to_be_visible()
        expect(self.page.get_by_label("fmc_login", exact=True)).to_have_count(0)
        expect(self.page.get_by_label("fmc_pass", exact=True)).to_have_count(0)

    def test_import_file_submission_and_results(self):
        self.home()
        self.page.get_by_role("link", name="Import data", exact=True).click()
        self.page.get_by_label("Import module", exact=True).select_option("url_import")
        expect(self.page.get_by_label("include_scheme", exact=True)).to_be_checked()
        self.page.get_by_role("button", name="Run import", exact=True).click()
        expect(self.page.get_by_role("alert")).to_contain_text("Choose a file")
        self.page.get_by_label("File to import", exact=True).set_input_files({"name": "urls.txt", "mimeType": "text/plain", "buffer": b"https://example.org/"})
        with self.page.expect_request("**/run_import") as submitted:
            self.page.route("**/run_import", lambda route: route.fulfill(status=201, content_type="application/json", body='{"id":"import-query"}'))
            self.page.get_by_role("button", name="Run import", exact=True).click()
        self.assertIn('filename="urls.txt"', submitted.value.post_data)
        self.page.wait_for_url(self.base + "/query/import-query")
        expect(self.page.locator(".eyebrow").filter(has_text="IMPORT RESULTS")).to_be_visible()
        expect(self.page.locator(".enrichment-attribute-card")).to_contain_text("https://example.org/")
        expect(self.page.get_by_role("button", name="Run same modules", exact=True)).to_have_count(0)
        expect(self.page.get_by_role("button", name="Run again", exact=True)).to_have_count(0)
        self.page.get_by_role("link", name="Choose modules", exact=True).click()
        expect(self.page.get_by_role("textbox", name="Indicator 1", exact=True)).to_have_value("https://example.org/")

    def test_import_paste_and_config_only_options(self):
        self.page.goto(self.base + "/import")
        self.page.get_by_label("Import module", exact=True).select_option("url_import")
        self.page.get_by_label("Input source", exact=True).select_option("paste")
        self.page.get_by_label("Data to import", exact=True).fill("https://example.org/café")
        self.page.get_by_label("include_scheme", exact=True).uncheck()
        self.page.route("**/run_import", lambda route: route.fulfill(status=400, content_type="application/json", body='{"message":"Import unavailable; try again."}'))
        with self.page.expect_request("**/run_import") as submitted:
            self.page.get_by_role("button", name="Run import", exact=True).click()
        self.assertIn('"include_scheme":"0"', submitted.value.post_data)
        self.assertIn("https://example.org/café", submitted.value.post_data)
        expect(self.page.get_by_role("alert")).to_contain_text("Import unavailable")
        expect(self.page.get_by_role("button", name="Run import", exact=True)).to_be_enabled()
        self.page.get_by_label("Import module", exact=True).select_option("remote_import")
        expect(self.page.get_by_label("Input source", exact=True)).to_have_count(0)
        self.page.get_by_label("report_id (required)", exact=True).fill("12")
        self.page.get_by_label("Override module settings", exact=True).check()
        self.page.get_by_label("apikey", exact=True).fill("test-only-key")
        with self.page.expect_request("**/run_import") as submitted:
            self.page.get_by_role("button", name="Run import", exact=True).click()
        self.assertIn('"report_id":"12"', submitted.value.post_data)
        self.assertIn('"apikey":"test-only-key"', submitted.value.post_data)
        expect(self.page.get_by_role("alert")).to_contain_text("Import unavailable")
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth + 1"))
        self.screenshot("import-mobile.png")

    def test_import_results_render_mixed_and_legacy_attributes(self):
        for result, objects in [
            ({"Attribute": [{"type": "domain", "value": "example.org"}], "Object": [{"name": "url", "Attribute": [{"type": "url", "value": "https://example.org/", "object_relation": "url"}]}]}, 1),
            ([{"types": "domain", "values": "example.org"}], 0),
        ]:
            with self.subTest(result=result):
                self.page.route("**/result/import-query", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"urls.txt": {"url_import": {"results": result}}})))
                self.page.goto(self.base + "/query/import-query")
                expect(self.page.locator(".enrichment-attribute-card")).to_have_count(1)
                expect(self.page.locator(".enrichment-attribute-card")).to_contain_text("example.org")
                expect(self.page.locator(".enrichment-object-card")).to_have_count(objects)
                self.page.unroute("**/result/import-query")

    def screenshot(self, name):
        if directory := os.environ.get("UI_SCREENSHOT_DIR"):
            Path(directory).mkdir(parents=True, exist_ok=True)
            self.page.evaluate("document.querySelectorAll('.toast').forEach(element => bootstrap.Toast.getOrCreateInstance(element).hide())")
            self.page.wait_for_function("!document.querySelector('.toast.show, .toast.showing')")
            self.page.locator("main").focus()
            self.page.evaluate("window.scrollTo(0, 0)")
            self.page.screenshot(path=str(Path(directory) / name), full_page=True)

    def test_admin_navigation_and_login(self):
        from app.utils import utils
        utils.ADMIN_PASSWORD = "local-test-password"
        try:
            self.home()
            expect(self.page.locator(".sidebar-link", has_text="Module configuration")).to_have_count(0)
            self.page.get_by_role("link", name="Admin login", exact=True).click()
            self.page.get_by_label("Password", exact=True).fill("local-test-password")
            self.page.get_by_role("button", name="Log in", exact=True).click()
            expect(self.page.locator(".sidebar-link", has_text="Module configuration")).to_be_visible()
            self.page.get_by_role("link", name="Log out", exact=True).click()
            expect(self.page.locator(".sidebar-link", has_text="Module configuration")).to_have_count(0)
        finally:
            utils.ADMIN_PASSWORD = None

    def test_login_input_survives_delayed_toast_initialization(self):
        from app.utils import utils
        utils.ADMIN_PASSWORD = "local-test-password"
        pending = []
        try:
            self.home()
            # The form is usable before the optional toast module finishes loading.
            # Hold its import to reproduce the timing seen on a fresh CI runner.
            self.page.route("**/static/js/toaster.js", lambda route: pending.append(route))
            self.page.goto(self.base + "/login", wait_until="commit")
            self.page.get_by_label("Password", exact=True).fill("local-test-password")
            self.page.get_by_label("Keep me logged in", exact=True).check()
            self.assertEqual(len(pending), 1)
            pending.pop().continue_()
            self.page.wait_for_load_state("load")
            self.page.unroute("**/static/js/toaster.js")
            await_toast = """async () => {
                const {display_toast} = await import('/static/js/toaster.js')
                await display_toast(new Response(JSON.stringify({message: 'Toast ready', toast_class: 'success-subtle'})))
            }"""
            self.page.evaluate(await_toast)
            expect(self.page.locator(".toast.show")).to_contain_text("Toast ready")
            expect(self.page.get_by_label("Password", exact=True)).to_have_value("local-test-password")
            expect(self.page.get_by_label("Keep me logged in", exact=True)).to_be_checked()
            self.page.get_by_role("button", name="Log in", exact=True).click()
            self.page.wait_for_url(self.base + "/")
            expect(self.page.get_by_role("link", name="Log out", exact=True)).to_be_visible()
        finally:
            for route in pending:
                route.abort()
            utils.ADMIN_PASSWORD = None

    @unittest.skipUnless(os.environ.get("AXE_SCRIPT_PATH"), "Set AXE_SCRIPT_PATH to an installed axe.min.js")
    def test_accessibility_scan(self):
        for path in ("/", "/import", "/export", "/modules_config", "/history", "/history_session", "/history_tree", "/external_tools", "/add_external_tool", "/login", "/query/test-query", "/query/object-query", "/query/import-query", "/query/export-query"):
            with self.subTest(path=path):
                self.page.goto(self.base + path + ("?sample=saved" if path in ("/history_session", "/history_tree") else ""))
                if path == "/":
                    self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
                    self.select_module("virustotal")
                if path == "/export":
                    self.page.get_by_label("Export module", exact=True).select_option("file_export")
                if path == "/modules_config":
                    self.page.get_by_role("button", name="virustotal", exact=False).click()
                if path == "/import":
                    self.page.get_by_label("Import module", exact=True).select_option("url_import")
                if path == "/query/export-query":
                    expect(self.page.get_by_role("link", name="Download event.txt", exact=True)).to_be_visible()
                elif path.startswith("/query/"):
                    expect(self.page.get_by_role("link", name="Choose modules", exact=True).first).to_be_visible()
                self.page.add_script_tag(path=os.environ["AXE_SCRIPT_PATH"])
                violations = self.page.evaluate("""async () => (await axe.run({runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => ({id: v.id, targets: v.nodes.map(n => n.target)}))""")
                self.assertEqual(violations, [])
                if path.startswith("/query/"):
                    for name in ("JSON", "Markdown"):
                        self.page.get_by_role("tab", name=name, exact=True).click()
                        violations = self.page.evaluate("""async () => (await axe.run({runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => ({id: v.id, targets: v.nodes.map(n => n.target)}))""")
                        self.assertEqual(violations, [], f"{name} result format")

    def sample_history(self, saved=False):
        self.page.goto(self.base + ("/history_tree?sample=saved" if saved else "/history_session?sample=session"))
        expect(self.page.locator(".investigation-choice")).to_have_count(3)
        self.page.locator(".investigation-choice").filter(has_text="circl.lu").click()
        expect(self.page.locator(".path-query-card")).to_have_count(6)

    def test_csv_downloads_from_legacy_and_object_results(self):
        for sid, expected in [("test-query", ["192.0.2.1"]), ("object-query", ["example.org", "443"])]:
            with self.subTest(sid=sid):
                self.page.goto(self.base + "/query/" + sid)
                csv_link = self.page.get_by_role("link", name="Download CSV", exact=True)
                expect(csv_link).to_be_visible()
                # Downloads remain available while changing result views.
                self.page.get_by_role("tab", name="JSON", exact=True).click()
                expect(csv_link).to_be_visible()
                with self.page.expect_download() as pending:
                    csv_link.click()
                download = pending.value
                self.assertTrue(download.suggested_filename.endswith(".csv"))
                data = Path(download.path()).read_text(encoding="utf-8")
                rows = list(csv.DictReader(io.StringIO(data)))
                self.assertTrue(set(expected).issubset({row["value"] for row in rows}))
                expect(self.page.get_by_role("link", name="Download JSON", exact=True)).to_be_visible()

    def test_investigation_paths_search_and_branch_controls(self):
        self.sample_history()
        expect(self.page.locator(".investigation-stats")).to_contain_text("12")
        expect(self.page.locator(".path-parent").first).to_contain_text("circl.lu")
        self.page.get_by_role("button", name="Collapse branches", exact=True).click()
        expect(self.page.locator(".path-query-card:visible")).to_have_count(1)
        self.page.get_by_role("button", name="Expand all", exact=True).click()
        expect(self.page.locator(".path-query-card:visible")).to_have_count(6)
        root_toggle = self.page.locator(".path-branch-toggle").first
        root_toggle.focus()
        self.page.keyboard.press("Enter")
        expect(root_toggle).to_have_attribute("aria-expanded", "false")
        self.page.get_by_role("searchbox", name="Search investigation paths").fill("circl_passivessl")
        expect(self.page.locator(".investigation-choice")).to_have_count(1)
        expect(self.page.locator(".path-query-card:visible")).to_have_count(3)
        expect(self.page.locator(".path-query-card.search-match")).to_have_count(1)
        expect(self.page.locator(".path-query-card").last).to_contain_text("192.0.2.14")
        self.assertNotIn("fixture-secret-not-for-display", self.page.locator("main").inner_text())
        self.page.get_by_role("searchbox", name="Search investigation paths").fill("no-such-indicator")
        expect(self.page.get_by_role("heading", name="No matching paths", exact=True)).to_be_visible()
        self.page.get_by_role("button", name="Clear search", exact=True).click()
        expect(self.page.locator(".investigation-choice")).to_have_count(3)

    def test_session_investigation_save_and_scoped_removal(self):
        self.sample_history()
        self.page.locator(".investigation-choice").nth(1).click()
        self.page.get_by_role("button", name="Save investigation", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Investigation saved.")).to_be_visible()
        self.page.get_by_role("button", name="Update saved tree", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Investigation saved.")).to_be_visible()
        self.page.goto(self.base + "/history_tree")
        expect(self.page.locator(".investigation-choice")).to_have_count(1)
        expect(self.page.locator(".path-query-card")).to_have_count(3)
        self.page.get_by_role("button", name="Remove query security@example.org", exact=True).click()
        expect(self.page.get_by_role("group", name="Confirm branch removal")).to_be_focused()
        self.page.get_by_role("button", name="Cancel", exact=True).click()
        expect(self.page.get_by_role("button", name="Remove query security@example.org", exact=True)).to_be_focused()
        self.page.get_by_role("button", name="Remove query security@example.org", exact=True).click()
        self.page.get_by_role("button", name="Remove branch", exact=True).click()
        expect(self.page.locator(".path-query-card")).to_have_count(2)
        self.page.reload()
        expect(self.page.locator(".path-query-card")).to_have_count(2)
        self.page.goto(self.base + "/history_session")
        expect(self.page.locator(".investigation-choice")).to_have_count(3)
        self.page.get_by_role("button", name="Remove query mail.circl.lu", exact=True).click()
        self.page.get_by_role("button", name="Remove branch", exact=True).click()
        expect(self.page.locator(".path-query-card")).to_have_count(4)
        self.page.reload()
        expect(self.page.locator(".path-query-card")).to_have_count(4)
        expect(self.page.locator(".investigation-choice")).to_have_count(3)

    def test_history_failures_keep_paths_and_allow_retry(self):
        self.page.route("**/get_history_tree", lambda route: route.abort())
        self.page.goto(self.base + "/history_tree?sample=saved")
        expect(self.page.get_by_role("alert")).to_be_visible()
        expect(self.page.get_by_role("heading", name="No investigation paths yet", exact=True)).to_have_count(0)
        self.page.unroute("**/get_history_tree")
        self.page.get_by_role("button", name="Try again", exact=True).click()
        expect(self.page.locator(".investigation-choice")).to_have_count(3)
        self.page.locator(".investigation-choice").filter(has_text="circl.lu").click()
        self.page.route("**/history/remove_node_tree/**", lambda route: route.fulfill(status=500, json={"message": "Could not remove branch"}))
        self.page.get_by_role("button", name="Remove query mail.circl.lu", exact=True).click()
        self.page.get_by_role("button", name="Remove branch", exact=True).click()
        expect(self.page.get_by_role("alert")).to_contain_text("Could not remove branch")
        expect(self.page.locator(".path-query-card")).to_have_count(6)
        expect(self.page.get_by_role("button", name="Remove branch", exact=True)).to_be_enabled()

    def test_populated_history_responsive_layouts(self):
        self.sample_history(saved=True)
        for width in (320, 768, 1440):
            self.page.set_viewport_size({"width": width, "height": 1100})
            self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"History overflows at {width}px")
            self.screenshot(f"investigation-trees-{width}.png")
        self.page.set_viewport_size({"width": 320, "height": 1000})
        self.page.get_by_role("combobox", name="Investigation", exact=True).select_option("00000000-0000-4000-8000-000000000301")
        expect(self.page.locator("#selected-path-heading")).to_contain_text("a3f8")
        self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"))
        self.page.goto(self.base + "/history_session")
        expect(self.page.get_by_role("button", name="Save investigation", exact=True)).to_be_visible()
        self.screenshot("session-history-320.png")
        self.page.set_viewport_size({"width": 1440, "height": 1100})
        self.screenshot("session-history-1440.png")

    def test_deep_history_paths_stay_readable_and_searchable(self):
        from history_samples import node
        path = node(999, "needle.example", "domain", ["dns"])
        for depth in range(11):
            path = node(900 + depth, "long-" + "a" * 160 + ".example", "hostname", ["circl_passivedns"], [path])
        self.page.route("**/get_history_tree", lambda route: route.fulfill(json=[path]))
        for width in (320, 768, 1440):
            self.page.set_viewport_size({"width": width, "height": 1000})
            self.page.goto(self.base + "/history_tree")
            expect(self.page.locator(".path-query-card")).to_have_count(12)
            self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"Deep path overflows at {width}px")
        self.page.get_by_role("button", name="Collapse branches", exact=True).click()
        expect(self.page.locator(".path-query-card:visible")).to_have_count(1)
        self.page.get_by_role("searchbox", name="Search investigation paths").fill("needle.example")
        expect(self.page.locator(".path-query-card:visible")).to_have_count(12)
        expect(self.page.locator(".path-query-card.search-match")).to_have_count(1)
        expect(self.page.locator(".investigation-search-row")).to_contain_text("1 matching queries")

    def test_removal_of_filtered_root_keeps_other_investigations(self):
        self.sample_history(saved=True)
        self.page.get_by_role("searchbox", name="Search investigation paths").fill("whois")
        expect(self.page.locator(".investigation-choice")).to_have_count(1)
        expect(self.page.locator(".path-query-card")).to_have_count(2)
        self.page.locator(".path-query-card").first.locator(".path-remove").click()
        expect(self.page.get_by_role("group", name="Confirm branch removal")).to_contain_text("branch of 3 queries")
        self.page.get_by_role("button", name="Remove branch", exact=True).click()
        expect(self.page.get_by_role("heading", name="No matching paths", exact=True)).to_be_visible()
        self.page.get_by_role("button", name="Clear search", exact=True).click()
        expect(self.page.locator(".investigation-choice")).to_have_count(2)
        self.page.reload()
        expect(self.page.locator(".investigation-choice")).to_have_count(2)
        self.page.goto(self.base + "/history_session")
        expect(self.page.locator(".investigation-choice")).to_have_count(3)

    def test_official_brand_assets_load(self):
        self.home()
        expect(self.page.locator(".brand img")).to_have_attribute("src", "/static/images/misp-modules-white.svg")
        expect(self.page.locator(".misp-project-brand img")).to_have_attribute("src", "/static/images/misp-logo-white.svg")
        self.assertEqual(self.page.locator("link[rel='icon']").get_attribute("href"), "/static/images/misp-modules-icon.svg")
        for image in self.page.locator(".brand img, .misp-project-brand img").all():
            self.assertTrue(image.evaluate("image => image.complete && image.naturalWidth > 0"))
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.locator(".mobile-brand img")).to_be_visible()
        expect(self.page.locator(".mobile-brand img")).to_have_attribute("src", "/static/images/misp-modules.svg")
        self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"))

    def test_visual_cards_preserve_values_and_related_queries(self):
        value = "https://example.org/a?owner=O'Reilly&tag=<img src=x onerror=window.injected=true>#frag"
        self.page.add_init_script("Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText: async value => { window.copiedValue = value }}})")
        self.page.route("**/result/test-query", lambda route: route.fulfill(json={"example.org": {"dns": {"results": [{"types": ["url"], "values": [value]}]}}}))
        self.page.goto(self.base + "/query/test-query")
        expect(self.page.locator(".enrichment-value")).to_have_text(value)
        expect(self.page.locator(".enrichment-value img")).to_have_count(0)
        self.assertIsNone(self.page.evaluate("window.injected"))
        self.page.get_by_role("button", name="Copy value", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Value copied.")).to_be_visible()
        self.assertEqual(self.page.evaluate("window.copiedValue"), value)
        choose = self.page.get_by_role("link", name="Choose modules", exact=True)
        self.assertEqual(parse_qs(urlparse(choose.get_attribute("href")).query)["query"][0], value)
        choose.click()
        expect(self.page.get_by_role("textbox", name="Indicator 1", exact=True)).to_have_value(value)
        self.page.goto(self.base + "/query/test-query")
        requests = []

        def submit(route):
            requests.append(route.request.post_data_json)
            route.fulfill(status=201, json={"id": "test-query"})

        self.page.route("**/run_modules", submit)
        self.page.get_by_role("button", name="Run same modules", exact=True).click()
        self.page.wait_for_url("**/query/test-query", wait_until="load")
        self.assertEqual(requests[0]["query"], [value])
        self.assertEqual(requests[0]["parent_id"], "test-query")

    def test_visual_action_failures_are_readable(self):
        self.page.add_init_script("Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText: async () => { throw new Error('Denied') }}})")
        self.page.goto(self.base + "/query/test-query")
        self.page.get_by_role("button", name="Copy value", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Unable to copy.")).to_be_visible()
        self.page.route("**/run_modules", lambda route: route.fulfill(status=400, json={"message": "Lookup unavailable"}))
        self.page.get_by_role("button", name="Run same modules", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Lookup unavailable")).to_be_visible()
        expect(self.page.get_by_role("button", name="Run same modules", exact=True)).to_be_enabled()

    def test_object_card_layout_and_attribute_types(self):
        for width in (320, 768, 1440):
            self.page.set_viewport_size({"width": width, "height": 1000})
            self.page.goto(self.base + "/query/object-query")
            expect(self.page.locator(".enrichment-object-card")).to_have_count(1)
            expect(self.page.locator(".enrichment-count")).to_have_text("6 attributes")
            expect(self.page.locator(".enrichment-field")).to_have_count(6)
            expect(self.page.get_by_text("Components extracted from the submitted URL.", exact=True)).to_be_visible()
            self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"Object output overflows at {width}px")
            self.screenshot(f"object-results-{width}.png")
        self.page.get_by_role("tab", name="JSON", exact=True).click()
        with self.page.expect_download() as downloaded:
            self.page.get_by_role("link", name="Download JSON", exact=True).click()
        result = json.loads(Path(downloaded.value.path()).read_text())
        self.assertIn("&view=details", result["results"]["Object"][0]["Attribute"][0]["value"])
        self.page.route("**/result/test-query", lambda route: route.fulfill(json={"example.org": {"dns": {"results": [
            {"types": ["counter"], "values": [0]},
            {"types": ["datetime"], "values": ["2026-10-27T12:00:00Z"]},
            {"types": ["text"], "values": [False, "Line one\nLine two", "a" * 256]},
        ]}}}))
        self.page.set_viewport_size({"width": 320, "height": 1000})
        self.page.goto(self.base + "/query/test-query")
        expect(self.page.locator(".enrichment-attribute-card")).to_have_count(5)
        expect(self.page.locator(".enrichment-value").nth(0)).to_have_text("0")
        expect(self.page.locator(".enrichment-value").nth(2)).to_have_text("false")
        self.assertEqual(self.page.locator(".enrichment-value").nth(3).text_content(), "Line one\nLine two")
        expect(self.page.locator(".enrichment-attribute-card").first.get_by_role("button", name="Run same modules", exact=True)).to_have_count(0)
        self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"))

    def test_validation_and_indicator_removal(self):
        self.home()
        run = self.page.get_by_role("button", name="Run enrichment", exact=True)
        run.click()
        expect(self.page.get_by_role("alert")).to_contain_text("Add at least one indicator")
        expect(self.page.get_by_role("alert")).to_be_focused()
        self.page.get_by_role("textbox", name="Indicator 1", exact=True).fill("example.org")
        run.click()
        expect(self.page.get_by_role("alert")).to_contain_text("Choose a MISP attribute")
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        run.click()
        expect(self.page.get_by_role("alert")).to_contain_text("Select at least one")
        self.page.get_by_role("button", name="Add indicator", exact=True).click()
        expect(self.page.get_by_role("textbox", name="Indicator 2", exact=True)).to_be_focused()
        self.page.get_by_role("button", name="Remove indicator 2", exact=True).click()
        expect(self.page.get_by_role("textbox", name="Indicator 1", exact=True)).to_have_value("example.org")
        expect(self.page.get_by_role("button", name="Remove indicator 1", exact=True)).to_have_count(0)

    def test_search_selection_and_attribute_switch(self):
        self.home()
        expect(self.page.get_by_text("Your modules will appear here")).to_be_visible()
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        expect(self.page.locator(".module-card")).to_have_count(3)
        self.page.get_by_role("searchbox", name="Search compatible modules").fill("registration details")
        expect(self.page.locator(".module-card")).to_have_count(1)
        self.page.get_by_role("button", name="Select visible", exact=True).click()
        expect(self.page.get_by_role("button", name="Remove module whois", exact=True)).to_be_visible()
        self.page.get_by_role("combobox", name="MISP attribute").select_option("sha256")
        expect(self.page.locator(".selected-module")).to_have_count(0)
        expect(self.page.locator(".module-card")).to_have_count(1)
        expect(self.page.locator(".module-name")).to_have_text("virustotal")
        self.page.get_by_role("searchbox", name="Search compatible modules").fill("does-not-exist")
        expect(self.page.get_by_text("No matching modules", exact=True)).to_be_visible()

    def test_configuration_payload_and_failed_submission_retry(self):
        self.home()
        self.page.get_by_role("textbox", name="Indicator 1", exact=True).fill(" example.org ")
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        self.select_module("virustotal")
        self.page.get_by_role("button", name="Run enrichment", exact=True).click()
        expect(self.page.get_by_text("Enter a value for apikey.", exact=True)).to_be_visible()
        expect(self.page.get_by_label("apikey", exact=True)).to_have_attribute("type", "password")
        self.page.get_by_label("apikey", exact=True).fill("test-only-key")
        requests = []

        def fail(route):
            requests.append(route.request.post_data_json)
            route.fulfill(status=503, json={"message": "Module service temporarily unavailable"})

        self.page.route("**/run_modules", fail)
        self.page.get_by_role("button", name="Run enrichment", exact=True).click()
        expect(self.page.get_by_role("alert")).to_contain_text("Module service temporarily unavailable")
        self.assertEqual(requests[0], {"query": ["example.org"], "input": "domain", "modules": ["virustotal"], "config": {"virustotal": {"apikey": "test-only-key"}}, "parent_id": ""})
        self.page.unroute("**/run_modules")
        self.page.route("**/run_modules", lambda route: route.fulfill(status=201, json={"id": "test-query"}))
        self.page.get_by_role("button", name="Run enrichment", exact=True).click()
        self.page.wait_for_url("**/query/test-query")
        expect(self.page.get_by_role("tab", name="JSON", exact=True)).to_be_visible()

    def test_pending_submission_is_not_duplicated(self):
        self.home()
        self.page.get_by_role("textbox", name="Indicator 1", exact=True).fill("example.org")
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        self.select_module("dns")
        routes = []
        self.page.route("**/run_modules", lambda route: routes.append(route))
        self.page.get_by_role("button", name="Run enrichment", exact=True).click()
        expect(self.page.get_by_role("button", name="Starting enrichment…", exact=True)).to_be_disabled()
        self.page.locator("form.enrichment-layout").evaluate("form => { form.requestSubmit(); form.requestSubmit() }")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].request.headers["x-csrftoken"], self.page.locator("#csrf_token").input_value())
        routes[0].fulfill(status=201, json={"id": "test-query"})
        self.page.wait_for_url("**/query/test-query")

    def test_catalogue_error_recovery_and_custom_configuration(self):
        self.page.route("**/get_modules", lambda route: route.abort())
        self.page.goto(self.base + "/")
        expect(self.page.get_by_role("alert")).to_contain_text("Unable to load modules")
        expect(self.page.get_by_role("button", name="Run enrichment", exact=True)).to_be_disabled()
        self.page.unroute("**/get_modules")
        self.page.get_by_role("button", name="Try again", exact=True).click()
        expect(self.page.get_by_role("combobox", name="MISP attribute")).to_be_enabled()
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        self.select_module("whois")
        expect(self.page.get_by_label("server", exact=True)).to_have_count(0)
        self.page.get_by_label("Override module settings").check()
        expect(self.page.get_by_label("server", exact=True)).to_be_visible()
        self.page.get_by_label("Override module settings").uncheck()
        expect(self.page.get_by_label("server", exact=True)).to_have_count(0)

    def test_module_settings_save_toggle_and_filter(self):
        self.page.goto(self.base + "/modules_config")
        self.page.get_by_role("button", name="whois", exact=False).click()
        self.page.get_by_label("server", exact=True).fill("whois.example.org")
        self.page.get_by_role("button", name="Save settings", exact=True).click()
        expect(self.page.get_by_role("status").filter(has_text="Module settings saved.")).to_be_visible()
        self.page.get_by_role("checkbox", name="Enable whois", exact=True).uncheck()
        self.page.get_by_role("combobox", name="Filter module status").select_option("disabled")
        expect(self.page.locator(".settings-row")).to_have_count(1)
        expect(self.page.locator(".settings-row")).to_contain_text("whois")
        self.page.get_by_role("checkbox", name="Enable whois", exact=True).check()
        expect(self.page.locator(".settings-row")).to_have_count(0)
        self.page.get_by_role("combobox", name="Filter module status").select_option("all")
        self.page.get_by_role("searchbox", name="Search modules", exact=True).fill("reputation")
        expect(self.page.locator(".settings-row")).to_have_count(1)
        self.page.get_by_role("button", name="virustotal", exact=False).click()
        self.page.get_by_label("Ask for configuration on each query").uncheck()
        expect(self.page.get_by_label("apikey", exact=True)).to_have_attribute("type", "password")
        self.screenshot("module-configuration.png")

    def test_module_settings_failures_preserve_state(self):
        self.page.goto(self.base + "/modules_config")
        self.page.route("**/change_status?*", lambda route: route.fulfill(status=500, json={"message": "Status update failed"}))
        self.page.get_by_role("checkbox", name="Enable dns", exact=True).uncheck()
        expect(self.page.get_by_role("checkbox", name="Enable dns", exact=True)).to_be_checked()
        expect(self.page.get_by_role("alert")).to_contain_text("Status update failed")
        self.page.get_by_role("button", name="whois", exact=False).click()
        self.page.get_by_label("server", exact=True).fill("unsaved.example.org")
        self.page.route("**/change_config", lambda route: route.fulfill(status=500, json={"message": "Save failed"}))
        self.page.get_by_role("button", name="Save settings", exact=True).click()
        expect(self.page.get_by_role("alert").filter(has_text="Save failed")).to_be_visible()
        expect(self.page.get_by_role("button", name="Save settings", exact=True)).to_be_enabled()
        self.page.reload()
        self.page.get_by_role("button", name="whois", exact=False).click()
        expect(self.page.get_by_label("server", exact=True)).not_to_have_value("unsaved.example.org")

    def test_parent_query_relationship_is_preserved(self):
        self.page.goto(self.base + "/home/test-query?query=example.org")
        expect(self.page.get_by_role("textbox", name="Indicator 1", exact=True)).to_have_value("example.org")
        self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
        self.select_module("dns")
        requests = []

        def submit(route):
            requests.append(route.request.post_data_json)
            route.fulfill(status=201, json={"id": "test-query"})

        self.page.route("**/run_modules", submit)
        self.page.get_by_role("button", name="Run enrichment", exact=True).click()
        self.page.wait_for_url("**/query/test-query")
        self.assertEqual(requests[0]["parent_id"], "test-query")

    def test_result_errors_are_grouped_without_duplicate_ids(self):
        self.page.route("**/result/test-query", lambda route: route.fulfill(json={
            "example.org": {"dns": {"results": [{"types": ["ip-dst"], "values": ["192.0.2.1"]}]}, "whois": {"error": "Lookup failed"}},
            "bad.example": {"virustotal": None},
        }))
        self.page.goto(self.base + "/query/test-query")
        expect(self.page.get_by_role("heading", name="Errors", exact=True)).to_be_visible()
        expect(self.page.locator(".result-errors")).to_contain_text("whois")
        expect(self.page.locator(".result-errors")).to_contain_text("virustotal")
        ids = self.page.locator("[id]").evaluate_all("elements => elements.map(element => element.id)")
        self.assertEqual(len(ids), len(set(ids)))
        expect(self.page.locator(".result-body > .accordion .accordion-item")).to_have_count(2)

    def test_result_formats_and_reuse_link(self):
        self.page.goto(self.base + "/query/test-query")
        expect(self.page.get_by_role("status").filter(has_text="Complete:")).to_be_visible()
        expect(self.page.get_by_role("heading", name="Errors", exact=True)).to_have_count(0)
        self.page.get_by_role("tab", name="JSON", exact=True).click()
        expect(self.page.get_by_role("link", name="Download JSON", exact=True)).to_be_visible()
        expect(self.page.get_by_role("tab", name="JSON", exact=True)).to_have_attribute("aria-selected", "true")
        self.page.get_by_role("tab", name="JSON", exact=True).focus()
        self.page.keyboard.press("ArrowRight")
        expect(self.page.get_by_role("tab", name="Markdown", exact=True)).to_be_focused()
        expect(self.page.get_by_role("tab", name="Markdown", exact=True)).to_have_attribute("aria-selected", "true")
        self.page.get_by_role("tab", name="Visual", exact=True).click()
        self.screenshot("enrichment-results.png")
        reuse = self.page.get_by_role("link", name="Reuse indicators", exact=True)
        self.assertEqual(json.loads(parse_qs(urlparse(reuse.get_attribute("href")).query)["query"][0]), ["example.org"])
        reuse.click()
        expect(self.page.get_by_role("textbox", name="Indicator 1", exact=True)).to_have_value("example.org")

    def test_responsive_pages_and_mobile_navigation(self):
        for width in (320, 768, 1440):
            self.page.set_viewport_size({"width": width, "height": 1000})
            for path in ("/", "/export", "/modules_config", "/history", "/history_session", "/history_tree", "/query/test-query", "/query/export-query", "/external_tools", "/add_external_tool", "/login", "/missing"):
                with self.subTest(width=width, path=path):
                    response = self.page.goto(self.base + path)
                    self.assertLess(response.status, 500)
                    expect(self.page.locator("h1").first).to_be_visible()
                    if path == "/export":
                        self.page.get_by_label("Export module", exact=True).select_option("file_export")
                    self.assertFalse(self.page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"Overflow at {width}px on {path}")
            self.page.goto(self.base + "/")
            self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
            self.page.get_by_role("textbox", name="Indicator 1", exact=True).fill("example.org")
            self.select_module("dns")
            self.screenshot(f"enrichment-{width}.png")
        self.page.set_viewport_size({"width": 320, "height": 800})
        self.page.get_by_role("button", name="Open navigation", exact=True).click()
        expect(self.page.get_by_role("button", name="Close navigation", exact=True)).to_have_attribute("aria-expanded", "true")
        expect(self.page.locator(".sidebar-link[aria-current='page']")).to_have_text("New enrichment")
        self.page.keyboard.press("Escape")
        expect(self.page.get_by_role("button", name="Open navigation", exact=True)).to_be_focused()
        expect(self.page.locator("#sidebar")).not_to_be_visible()


if __name__ == "__main__":
    unittest.main()
