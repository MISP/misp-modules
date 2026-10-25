import base64
import copy
import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import osquery
from misp_modules.modules.action_mod import osquery_pack_publish as publish
from misp_modules.modules.export_mod import osqueryexport as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "uuid": "attribute-1", "to_ids": True, **metadata}


def event(attributes=None, **metadata):
    return {"uuid": "event-1", "Attribute": [attribute()] if attributes is None else attributes, **metadata}


def run_export(data=None, **config):
    result = export.handler(json.dumps({"data": event() if data is None else data, "config": config}))
    assert "error" not in result, result
    return base64.b64decode(result["data"], validate=True).decode(), result


def run_action(data=None, **params):
    return publish.handler(
        json.dumps({"data": event() if data is None else data, "params": {"pack_name": "test", **params}})
    )


@pytest.fixture
def database():
    # Column names captured from the tagged upstream schema, not from our SQL generator.
    schema = json.loads((Path(__file__).parent / "test_files/osquery_5_24_schema.json").read_text())
    with sqlite3.connect(":memory:") as db:
        for table, spec in schema["tables"].items():
            columns = ", ".join(f'"{column}"' for column in spec["columns"])
            db.execute(f'CREATE TABLE "{table}" ({columns})')
        yield db


SAMPLES = [
    ("regkey", r"HKLM\Software\Bad"),
    ("regkey|value", r"HKCU\Software\Bad|data|with|pipes"),
    ("mutex", "evil_mutex"),
    ("windows-service-displayname", "Bad service"),
    ("windows-service-name", "BadSvc"),
    ("windows-scheduled-task", "Bad task"),
    ("named pipe", "evil_pipe"),
    ("domain", "example.org"),
    ("ip-src", "2001:db8::1"),
    ("ip-dst", "192.0.2.1"),
    ("filename", "/tmp/evil"),
    ("filename", "evil"),
    ("sha256", "a" * 64),
    ("yara", "rule test { condition: true }"),
]


@pytest.mark.parametrize("kind,value", SAMPLES)
def test_every_query_compiles_against_current_upstream_columns(database, kind, value):
    sql, _ = osquery.query(kind, value, "/tmp/%%")
    database.execute(sql)


@pytest.mark.parametrize(
    "kind,table,column",
    [
        ("windows-service-name", "services", "name"),
        ("windows-service-displayname", "services", "display_name"),
        ("named pipe", "pipes", "name"),
        ("domain", "dns_cache", "name"),
    ],
)
def test_indicator_quotes_and_wildcards_are_literal(database, kind, table, column):
    value = "evil_%'; DROP TABLE services; --"
    database.execute(f'INSERT INTO "{table}" ("{column}") VALUES (?)', (value,))
    database.execute(f'INSERT INTO "{table}" ("{column}") VALUES (?)', ("evil_other",))
    rows = database.execute(osquery.query(kind, value)[0]).fetchall()
    assert len(rows) == 1
    assert value in rows[0]
    database.execute("SELECT * FROM services")


@pytest.mark.parametrize(
    "indicator,cached_name",
    [("EXAMPLE.ORG", "example.org"), ("example.org", "EXAMPLE.ORG"), ("ExAmPlE.OrG", "eXaMpLe.oRg")],
)
def test_domain_matches_ignore_case_but_require_the_whole_name(database, indicator, cached_name):
    database.executemany(
        "INSERT INTO dns_cache (name) VALUES (?)",
        [(cached_name,), ("sub." + cached_name,), (cached_name + ".attacker.test",)],
    )
    sql, platform = osquery.query("domain", indicator)
    assert database.execute(sql).fetchall() == [(cached_name, None, None)]
    assert platform == "windows"


def test_registry_key_semantics_hkcu_and_composite_separator(database):
    database.execute(
        "INSERT INTO registry (key, path, type) VALUES (?, ?, ?)", ("HKEY_USERS", r"HKEY_USERS\S-1-5-21", "subkey")
    )
    database.execute("INSERT INTO registry (key, data) VALUES (?, ?)", (r"HKEY_USERS\S-1-5-21\Software\my_key%", "a|b"))
    database.execute("INSERT INTO registry (key, data) VALUES (?, ?)", (r"HKEY_USERS\S-1-5-21\Software\myXkeyX", "a|b"))
    sql, _ = osquery.query("regkey|value", r"HKCU\Software\my_key%|a|b")
    assert len(database.execute(sql).fetchall()) == 1
    assert "key = 'HKEY_LOCAL_MACHINE\\Software\\HKCU'" in osquery.query("regkey", r"HKLM\Software\HKCU")[0]


def test_mutex_filters_object_type(database):
    database.execute("INSERT INTO winbaseobj (object_name, object_type) VALUES ('same', 'Event'), ('same', 'Mutant')")
    assert len(database.execute(osquery.query("mutex", "same")[0]).fetchall()) == 1


def test_default_is_pack_with_platforms_and_intervals():
    text, result = run_export(
        event([attribute(kind, value) for kind, value in SAMPLES]), scan_path="/tmp/%%", interval="600"
    )
    pack = json.loads(text)
    assert len(pack["queries"]) == len(SAMPLES)
    assert result["summary"]["skipped"] == {}
    for item in pack["queries"].values():
        assert item["interval"] == 600 and item["removed"] is False
        if "FROM services" in item["query"] or "FROM dns_cache" in item["query"]:
            assert item["platform"] == "windows"
        if "JOIN yara_file" in item["query"]:
            assert item["version"] == "5.24.0" and item["platform"] == "posix"
    assert export.introspection()["responseType"] == "application/json"


@pytest.mark.parametrize("scope,platform", [("/tmp/%%", "posix"), (r"C:\Temp\%%", "windows")])
def test_scans_are_scoped_and_hashes_do_not_limit_matches(scope, platform):
    sql, actual_platform = osquery.query("sha256", "A" * 64, scope)
    assert scope in sql and actual_platform == platform
    assert "LIMIT" not in sql and "file.path = hash.path" in sql
    assert "'" + "a" * 64 + "'" in sql


def test_sql_mode_and_missing_scan_scope():
    data = event(
        [
            attribute(),
            attribute("sha256", "a" * 64),
            attribute("yara", "rule x { condition: true }"),
            attribute("filename", "evil"),
        ]
    )
    text, result = run_export(data, format="sql")
    assert text == "SELECT * FROM process_open_sockets WHERE remote_address = '192.0.2.1';\n"
    assert result["summary"]["skipped"]["scan_path required for file scans."] == 3
    assert result["warnings"]


@pytest.mark.parametrize(
    "wrap",
    [
        lambda e: e,
        lambda e: {"Event": e},
        lambda e: [{"Event": e}],
        lambda e: {"Event": {"uuid": e["uuid"]}, "Attribute": e["Attribute"], "Object": e["Object"]},
    ],
)
def test_event_shapes_objects_ids_deleted_and_deduplication(wrap):
    data = event(
        [attribute(), attribute(to_ids=False), attribute(deleted="1"), attribute("text", "unsupported")],
        Object=[
            {"uuid": "obj-1", "Attribute": [attribute(uuid="object-attr")]},
            {"deleted": True, "Attribute": [attribute(value="192.0.2.99")]},
        ],
    )
    original = copy.deepcopy(data)
    text, result = run_export(wrap(data))
    assert len(json.loads(text)["queries"]) == 1
    refs = next(iter(result["sources"].values()))
    assert len(refs) == 2 and refs[1]["object"] == "obj-1"
    assert data == original


def test_non_ids_opt_in_and_deleted_events():
    data = event([attribute(to_ids="0")])
    assert not json.loads(run_export(data)[0])["queries"]
    assert json.loads(run_export(data, include_non_ids=True)[0])["queries"]
    assert not json.loads(run_export(event(deleted="1"))[0])["queries"]


def test_names_are_stable_across_reordering():
    data = [attribute(), attribute("domain", "example.org")]
    assert run_export(event(data))[0] == run_export(event(data[::-1]))[0]


@pytest.mark.parametrize(
    "config",
    [
        {"interval": 0},
        {"interval": True},
        {"interval": "1.5"},
        {"interval": 604801},
        {"format": "xml"},
        {"scan_path": "relative/%"},
        {"include_non_ids": "maybe"},
    ],
)
def test_invalid_export_settings(config):
    assert "error" in export.handler(json.dumps({"data": event(), "config": config}))


@pytest.mark.parametrize("data", [None, "bad", [False], {"Event": []}, {"Attribute": {}}, {"Object": [None]}])
def test_malformed_envelopes(data):
    assert "error" in export.handler(json.dumps({"data": data}))


@pytest.mark.parametrize(
    "kind,value",
    [("ip-dst", "bad"), ("sha256", "bad"), ("regkey|value", "bad"), ("filename", "bad\x00"), ("domain", None)],
)
def test_malformed_attributes_are_reported(kind, value):
    text, result = run_export(event([attribute(kind, value)]), scan_path="/tmp/%%")
    assert not json.loads(text)["queries"] and result["warnings"]


def test_query_limit(monkeypatch):
    monkeypatch.setattr(osquery, "MAX_QUERIES", 1)
    assert "error" in export.handler(json.dumps({"data": event([attribute(), attribute("domain", "example.org")])}))


def test_action_dry_run_matches_export_without_directory(monkeypatch):
    monkeypatch.delenv("OSQUERY_PACK_DIRECTORY", raising=False)
    result = run_action()["data"]
    text, _ = run_export()
    assert result["status"] == "planned" and result["pack"] == json.loads(text)
    assert result["sha256"] == hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize("setting", [None, "", "true", True])
def test_blank_or_enabled_dry_run_never_writes(monkeypatch, setting):
    monkeypatch.delenv("OSQUERY_PACK_DIRECTORY", raising=False)
    assert run_action(dry_run=setting)["data"]["status"] == "planned"


def test_action_publish_no_clobber_and_explicit_snapshot_replace(tmp_path, monkeypatch):
    monkeypatch.setenv("OSQUERY_PACK_DIRECTORY", str(tmp_path))
    result = run_action(dry_run=False)
    assert result["data"]["status"] == "published"
    target = tmp_path / "misp-test.conf"
    original = target.read_bytes()
    assert json.loads(original) == result["data"]["pack"]
    assert target.stat().st_mode & 0o777 == 0o640
    assert "error" in run_action(event([attribute(value="192.0.2.2")]), dry_run="false")
    assert target.read_bytes() == original
    assert (
        run_action(event([attribute(value="192.0.2.2")]), dry_run=False, overwrite=True)["data"]["status"]
        == "published"
    )
    assert target.read_bytes() != original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["misp-test.conf"]


def test_action_refuses_empty_replacement_and_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("OSQUERY_PACK_DIRECTORY", str(tmp_path))
    other = tmp_path / "other"
    other.write_text("untouched")
    target = tmp_path / "misp-test.conf"
    target.symlink_to(other)
    assert "error" in run_action(dry_run=False, overwrite=True)
    assert other.read_text() == "untouched"
    target.unlink()
    assert "error" in run_action(event([]), dry_run=False, overwrite=True)
    assert not target.exists()


def test_atomic_failure_preserves_existing_pack_and_cleans_temporary_file(tmp_path, monkeypatch):
    monkeypatch.setenv("OSQUERY_PACK_DIRECTORY", str(tmp_path))
    target = tmp_path / "misp-test.conf"
    target.write_text("old")

    def fail(*args):
        raise OSError("simulated failure")

    monkeypatch.setattr(publish.os, "replace", fail)
    assert "error" in run_action(dry_run=False, overwrite=True)
    assert target.read_text() == "old" and len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize("name", ["../escape", "/tmp/escape", "a.conf", "", None, "a" * 65])
def test_action_rejects_invalid_names(name):
    assert "error" in run_action(pack_name=name)


def test_action_requires_server_directory_and_rejects_filtered_data(monkeypatch):
    monkeypatch.delenv("OSQUERY_PACK_DIRECTORY", raising=False)
    assert "error" in run_action(dry_run=False)
    for field in ("filteredItems", "matchingData"):
        assert "error" in publish.handler(json.dumps({"data": event(), "params": {"pack_name": "test"}, field: []}))
    assert "error" in run_action(dry_run="maybe")
    assert export.handler() is False and publish.handler() is False


class TestOsqueryHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "osqueryexport": export,
                "type:osqueryexport": "export_mod",
                "osquery_pack_publish": publish,
                "type:osquery_pack_publish": "action_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_workflow_contract(self):
        descriptors = {item["name"]: item for item in json.loads(self.fetch("/modules").body)}
        assert descriptors["osquery_pack_publish"]["meta"]["config"]["expect_misp_core_format"] is True
        for name in descriptors:
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": name, "data": event(), "params": {"pack_name": "test"}}),
            )
            assert response.code == 200 and "error" not in json.loads(response.body)


@pytest.mark.skipif(not os.getenv("OSQUERYI"), reason="Set OSQUERYI to run against an installed osquery binary")
def test_real_osquery_file_hash_yara_and_config(tmp_path, monkeypatch):
    binary = os.environ["OSQUERYI"]
    sample = tmp_path / "sample's_file"
    sample.write_text("osquery integration fixture")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    yara = 'rule test { strings: $a = "osquery integration fixture" condition: $a }'
    attrs = [
        attribute("filename", str(sample)),
        attribute("filename", sample.name),
        attribute("sha256", digest),
        attribute("yara", yara),
    ]
    pack, summary, _ = osquery.build(event(attrs), {"scan_path": str(tmp_path) + "/%"})
    assert summary["queries"] == 4
    for item in pack["queries"].values():
        process = subprocess.run(
            [binary, "--json", item["query"]], capture_output=True, text=True, check=True, timeout=30
        )
        rows = json.loads(process.stdout)
        assert rows and rows[0]["path"] == str(sample), process.stderr
    config = tmp_path / "osquery.conf"
    config.write_text(json.dumps({"packs": {"misp": pack}}))
    subprocess.run([binary, "--config_check", f"--config_path={config}"], capture_output=True, check=True, timeout=30)
    monkeypatch.setenv("OSQUERY_PACK_DIRECTORY", str(tmp_path))
    published = run_action(
        event(attrs + [attribute("windows-service-name", "BadService")]), scan_path=str(tmp_path) + "/%", dry_run=False
    )
    assert "error" not in published
    config.write_text(json.dumps({"packs": {"misp": str(tmp_path / published["data"]["filename"])}}))
    subprocess.run([binary, "--config_check", f"--config_path={config}"], capture_output=True, check=True, timeout=30)
