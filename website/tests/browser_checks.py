"""Browser regression tests against real Flask templates and isolated fixture data.

Run: python -m unittest discover -s website/tests -p 'browser_checks.py' -v
Requires website dependencies, playwright, and Chromium (see doc/interface.md).
"""
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

    @unittest.skipUnless(os.environ.get("AXE_SCRIPT_PATH"), "Set AXE_SCRIPT_PATH to an installed axe.min.js")
    def test_accessibility_scan(self):
        for path in ("/", "/modules_config", "/history", "/history_session", "/history_tree", "/external_tools", "/add_external_tool", "/login", "/query/test-query"):
            with self.subTest(path=path):
                self.page.goto(self.base + path)
                if path == "/":
                    self.page.get_by_role("combobox", name="MISP attribute").select_option("domain")
                    self.select_module("virustotal")
                if path == "/modules_config":
                    self.page.get_by_role("button", name="virustotal", exact=False).click()
                if path == "/query/test-query":
                    expect(self.page.get_by_role("link", name="query", exact=True)).to_be_visible()
                self.page.add_script_tag(path=os.environ["AXE_SCRIPT_PATH"])
                violations = self.page.evaluate("""async () => (await axe.run({runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => ({id: v.id, targets: v.nodes.map(n => n.target)}))""")
                self.assertEqual(violations, [])
                if path == "/query/test-query":
                    for name in ("JSON", "Markdown"):
                        self.page.get_by_role("tab", name=name, exact=True).click()
                        violations = self.page.evaluate("""async () => (await axe.run({runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => ({id: v.id, targets: v.nodes.map(n => n.target)}))""")
                        self.assertEqual(violations, [], f"{name} result format")

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
        expect(self.page.get_by_role("link", name="Download", exact=True)).to_be_visible()
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
            for path in ("/", "/modules_config", "/history", "/history_session", "/history_tree", "/query/test-query", "/external_tools", "/add_external_tool", "/login", "/missing"):
                with self.subTest(width=width, path=path):
                    response = self.page.goto(self.base + path)
                    self.assertLess(response.status, 500)
                    expect(self.page.locator("h1").first).to_be_visible()
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
