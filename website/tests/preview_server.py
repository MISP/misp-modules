"""Run the actual Flask website with isolated data for UI regression tests.

The module catalogue and query execution use fixtures. All templates, database
configuration, CSRF protection, and other routes use the real Flask application.
No module daemon, credentials, or external services are used.
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

MODULES = [
    {"name": "dns", "mispattributes": {"input": ["domain", "hostname"]}, "meta": {"description": "Resolve domains and hostnames into IP addresses.", "config": [], "module-type": ["expansion"]}},
    {"name": "whois", "mispattributes": {"input": ["domain", "ip-dst"]}, "meta": {"description": "Look up registration details and ownership information.", "config": ["server"], "module-type": ["expansion"]}},
    {"name": "virustotal", "mispattributes": {"input": ["domain", "ip-dst", "sha256", "url"]}, "meta": {"description": "Investigate reputation, detections, and related indicators.", "config": ["apikey"], "module-type": ["expansion"]}},
    {"name": "url_import", "mispattributes": {"inputSource": ["file", "paste"], "format": "misp_standard", "userConfig": {"include_scheme": {"type": "Boolean", "message": "Include scheme", "checked": "True"}}}, "meta": {"description": "Import URLs from text.", "config": [], "module-type": ["import"]}},
    {"name": "remote_import", "mispattributes": {"inputSource": [], "userConfig": {"report_id": {"type": "Integer", "message": "Report identifier", "required": True}}}, "meta": {"description": "Import a remote report.", "config": ["apikey"], "module-type": ["import"]}},
]


OBJECT_RESULT = {"results": {"Object": [{
    "name": "url", "description": "Components extracted from the submitted URL.",
    "Attribute": [
        {"object_relation": "url", "type": "url", "value": "https://example.org/a/very/long/path?search=threat+intelligence&view=details", "comment": "Source URL supplied to the enrichment."},
        {"object_relation": "domain", "type": "domain", "value": "example.org"},
        {"object_relation": "scheme", "type": "text", "value": "https"},
        {"object_relation": "port", "type": "port", "value": 443},
        {"object_relation": "resource_path", "type": "text", "value": "/a/very/long/path"},
        {"object_relation": "query_string", "type": "text", "value": "search=threat+intelligence&view=details"},
    ],
}]}}


def create_fixture_app(database_path):
    os.environ["SECRET_KEY"] = "local-ui-test-only"
    os.environ["DATABASE_URI"] = f"sqlite:///{database_path}"
    from app import create_app, db
    from app.models import Module, Session_db
    from app.utils import utils
    from app.utils.init_modules import create_modules_db

    utils.MODULES = MODULES
    utils.ADMIN_PASSWORD = None
    app = create_app()
    app.config["TESTING"] = True

    @app.before_request
    def fixture_enrichment():
        from flask import request
        if request.args.get("sample") in ("session", "saved"):
            from history_samples import seed_history_samples
            seed_history_samples(request.args["sample"])
        if request.endpoint == "home.run_modules":
            return {"id": "test-query"}, 201

    with app.app_context():
        db.create_all()
        create_modules_db()
        Module.query.filter_by(name="virustotal").first().request_on_query = True
        db.session.add(Session_db(
            uuid="test-query", query_enter=json.dumps(["example.org"]),
            modules_list=json.dumps(["dns"]), input_query="domain", nb_errors=0,
            query_date=datetime(2026, 10, 27, 12), config_module="{}",
            result=json.dumps({"example.org": {"dns": {"results": [{"types": ["ip-dst"], "values": ["192.0.2.1"]}]}}}),
        ))
        db.session.add(Session_db(
            uuid="import-query", query_enter=json.dumps(["urls.txt"]),
            modules_list=json.dumps(["url_import"]), input_query="import", nb_errors=0,
            query_date=datetime(2026, 10, 27, 12), config_module="{}",
            result=json.dumps({"urls.txt": {"url_import": {"results": {"Attribute": [{"type": "url", "value": "https://example.org/"}], "Object": []}}}}),
        ))
        db.session.add(Session_db(
            uuid="object-query", query_enter=json.dumps([OBJECT_RESULT["results"]["Object"][0]["Attribute"][0]["value"]]),
            modules_list=json.dumps(["extract_url_components"]), input_query="url", nb_errors=0,
            query_date=datetime(2026, 10, 27, 12), config_module="{}",
            result=json.dumps({OBJECT_RESULT["results"]["Object"][0]["Attribute"][0]["value"]: {"extract_url_components": OBJECT_RESULT}}),
        ))
        db.session.commit()
    return app


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7010)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="misp-modules-ui-") as directory:
        create_fixture_app(Path(directory) / "preview.sqlite").run(host="127.0.0.1", port=args.port, debug=False)
