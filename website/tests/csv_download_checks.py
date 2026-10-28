"""Exercise actual Flask downloads with both result formats and storage paths."""

import csv
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import home, session_class


def make_client(storage):
    app = Flask(__name__)
    app.register_blueprint(home.home_blueprint)
    results = {
        "https://example.org/?a=1&b=2": {
            "legacy": {
                "results": [
                    {
                        "types": ["domain", "hostname"],
                        "values": ["café.example", "=1+1"],
                        "comment": "seen, twice",
                    }
                ]
            },
            "standard": {
                "results": {
                    "Attribute": [{"type": "text", "value": "standalone"}],
                    "Object": [
                        {
                            "name": "url",
                            "uuid": "object-1",
                            "Attribute": [
                                {
                                    "type": "port",
                                    "value": 443,
                                    "object_relation": "port",
                                }
                            ],
                        }
                    ],
                }
            },
            "empty": {"results": []},
            "error": {"error": "failed"},
            "invalid": {"results": "invalid"},
            "metadata-only": {"results": {"unsupported": []}},
        }
    }
    saved = SimpleNamespace(result=json.dumps(results))
    live = SimpleNamespace(uuid="session-1", result=results)
    patches = [
        patch.object(
            home.HomeModel,
            "get_session",
            side_effect=lambda sid: (
                saved if sid == "session-1" and storage == "saved" else None
            ),
        ),
        patch.object(session_class, "sessions", [live] if storage == "live" else []),
    ]
    for item in patches:
        item.start()
    return app.test_client(), patches


def download(client, module="legacy", format_name="csv", sid="session-1"):
    return client.get(
        f"/download/{sid}?"
        + urlencode(
            {
                "query": "https://example.org/?a=1&b=2",
                "module": module,
                "format": format_name,
            }
        )
    )


def rows(response):
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert ".csv" in response.headers["Content-Disposition"]
    return list(csv.DictReader(io.StringIO(response.data.decode("utf-8"), newline="")))


class CSVDownloadChecks:
    def setUp(self):
        self.client, patches = make_client(self.storage)
        for item in patches:
            self.addCleanup(item.stop)

    def test_legacy_download_and_source_context(self):
        result = rows(download(self.client))
        assert [(row["type"], row["value"]) for row in result] == [
            ("domain", "café.example"),
            ("domain", "'=1+1"),
            ("hostname", "café.example"),
            ("hostname", "'=1+1"),
        ]
        assert result[0]["event_info"] == "legacy: https://example.org/?a=1&b=2"
        assert result[0]["comment"] == "seen, twice"

    def test_standard_attributes_and_objects(self):
        result = rows(download(self.client, "standard"))
        assert [row["value"] for row in result] == ["standalone", "443"]
        assert result[1]["object_name"] == "url"
        assert result[1]["object_uuid"] == "object-1"
        assert result[1]["object_relation"] == "port"

    def test_empty_results_have_a_header(self):
        assert rows(download(self.client, "empty")) == []

    def test_json_download_is_preserved(self):
        response = download(self.client, format_name="json")
        assert response.status_code == 200
        assert response.get_json()["results"][0]["values"] == ["café.example", "=1+1"]
        assert ".json" in response.headers["Content-Disposition"]

    def test_unexportable_result_returns_an_error(self):
        for module in ["error", "invalid", "metadata-only", "missing"]:
            with self.subTest(module=module):
                self.assertEqual(download(self.client, module).status_code, 400)

    def test_unknown_session_and_format_and_missing_arguments(self):
        assert download(self.client, sid="missing").status_code == 404
        assert download(self.client, format_name="xml").status_code == 400
        assert self.client.get("/download/session-1").status_code == 400
        assert (
            self.client.get("/download/session-1?module=legacy&format=csv").status_code
            == 400
        )


class SavedCSVDownloadChecks(CSVDownloadChecks, unittest.TestCase):
    storage = "saved"


class LiveCSVDownloadChecks(CSVDownloadChecks, unittest.TestCase):
    storage = "live"
