import base64
import copy
import json
import re
from pathlib import Path

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import defender_endpoint_export as defender

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SCHEMAS = json.loads((Path(__file__).parent / "fixtures/defender_kql/schemas.json").read_text())


def attribute(kind="domain", value="example.org", **kwargs):
    return dict(type=kind, value=value, **kwargs)


def export(attributes=None, config=None, data=None):
    request = {"data": data if data is not None else [{"Attribute": attributes or []}]}
    if config is not None:
        request["config"] = config
    result = defender.handler(json.dumps(request))
    assert "error" not in result, result
    return base64.b64decode(result["data"]).decode().splitlines(), result["summary"]


def test_sha256_query_uses_sha256_columns():
    (query,), _ = export([attribute("sha256", SHA256.upper())])
    assert f'dynamic(["{SHA256}"])' in query
    assert "SHA256 in~ (MISP_sha256)" in query
    assert "InitiatingProcessSHA256 in~ (MISP_sha256)" in query
    assert "SHA1" not in query
    assert "DeviceNetworkEvents" in query


@pytest.mark.parametrize("kind,length", [("md5", 32), ("sha1", 40), ("sha256", 64)])
def test_hashes_only_use_documented_columns(kind, length):
    (query,), _ = export([attribute(kind, "A" * length)], {"tables": list(SCHEMAS)})
    for branch in query.split(" union withsource=MISP_SourceTable ")[1].split(", ("):
        table = re.search(r"\(?([A-Za-z]+) \|", branch)[1]
        fields = re.findall(r"(\w+) in~ \(MISP_", branch)
        assert fields and all(field in SCHEMAS[table]["columns"] for field in fields)
    assert "AlertInfo" not in query and "DeviceAlertEvents" not in query
    assert ("AlertEvidence" in query) == (kind != "md5")


def test_every_table_branch_is_time_filtered_before_all_indicator_predicates():
    (query,), _ = export(
        [attribute("url", "https://example.org/a"), attribute("domain"), attribute("ip-dst", "192.0.2.1")],
        {"tables": list(SCHEMAS)},
    )
    branches = query.split(" union withsource=MISP_SourceTable ")[1].split(", (")
    assert len(branches) == 6
    for branch in branches:
        assert " | where Timestamp between (MISP_Start .. MISP_End) | where (" in branch
        assert branch.endswith("))")
    assert "contains 'example.org'" not in query and "RemoteUrl has" not in query
    assert "let MISP_Start = ago(7d); let MISP_End = now();" in query


def test_domain_and_url_dispatch_have_distinct_host_and_literal_semantics():
    (domain,), _ = export([attribute(value="Example.ORG.")], {"tables": "DeviceNetworkEvents"})
    assert 'MISP_domain = dynamic(["example.org"])' in domain
    assert "MISP_Host(RemoteUrl) in (MISP_domain)" in domain
    assert "MISP_DomainPattern" not in domain
    (url,), _ = export([attribute("url", "https://example.org/Case?q=Example")])
    assert 'MISP_url = dynamic(["https://example.org/Case?q=Example"])' in url
    assert "RemoteUrl in (MISP_url)" in url and "FileOriginReferrerUrl in (MISP_url)" in url
    assert "MISP_Host" not in url and " in~ " not in url


def test_subdomains_pattern_uses_an_escaped_label_boundary_and_the_extracted_host():
    (query,), _ = export([attribute()], {"domain_mode": "subdomains", "tables": "DeviceNetworkEvents"})
    literal = re.search(r"let MISP_DomainPattern = '([^']*)';", query)[1]
    pattern = literal.replace("\\\\", "\\")
    for host in ("example.org", "a.example.org", "deep.a.example.org"):
        assert re.search(pattern, host)
    for host in ("badexample.org", "example.org.evil.test", "exampleXorg", "unrelated.test"):
        assert not re.search(pattern, host)
    assert "MISP_Host(RemoteUrl) matches regex MISP_DomainPattern" in query
    assert "parse_url(" in query and ").Host" in query


def test_idna_is_nontransitional_and_url_values_remain_exact():
    (query,), _ = export([attribute(value="faß.de")])
    assert "xn--fa-hia.de" in query and "fass.de" not in query
    url = 'https://example.org/a\'\\b?x="c";|union DeviceEvents'
    # Whitespace is not valid in a URL; a valid literal can still contain KQL-looking punctuation.
    url = url.replace(" ", "%20")
    (query,), _ = export([attribute("url", url)])
    encoded = re.search(r"let MISP_url = dynamic\((\[.*?\])\);", query)[1]
    assert json.loads(encoded) == [url]
    assert query.count(" union withsource=") == 1


@pytest.mark.parametrize("kind,field", [("ip-src", "LocalIP"), ("ip-dst", "RemoteIP")])
def test_ip_direction_and_ipv6_semantic_comparison(kind, field):
    (query,), _ = export(
        [attribute(kind, "192.0.2.1"), attribute(kind, "2001:0DB8:0:0::1")],
        {"tables": "DeviceNetworkEvents"},
    )
    assert f"{field} in ('192.0.2.1')" in query
    assert f"ipv6_is_match({field}, '2001:db8::1')" in query
    assert ("RemoteIP" if kind == "ip-src" else "LocalIP") not in query


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_deletion_at_every_level(flag):
    data = [
        {"deleted": flag, "Event": "not inspected"},
        {"Event": {"deleted": flag, "Attribute": "not inspected"}},
        {"Attribute": [attribute(deleted=flag)], "Object": [{"deleted": flag, "Attribute": "not inspected"}]},
        {
            "Object": [
                {
                    "Attribute": [
                        attribute(value="removed.test", deleted=flag),
                        attribute(value="kept.test", deleted="0"),
                    ]
                }
            ]
        },
    ]
    (query,), summary = export(data=data)
    assert "kept.test" in query and "removed.test" not in query and "example.org" not in query
    assert summary["skipped"] == {"deleted events": 2, "deleted objects": 1, "deleted attributes": 2}


def test_event_layouts_deduplication_order_and_no_input_mutation():
    event = {
        "Attribute": [attribute(value="Example.org."), attribute(value="example.org", to_ids=False)],
        "Object": [{"Attribute": [attribute("sha256", SHA256)]}],
    }
    data = [event, {"Event": event}, {"Event": {"id": "1"}, **event}]
    original = copy.deepcopy(data)
    queries, summary = export(data=data)
    assert summary == {"indicators": 2, "queries": 1, "skipped": {}}
    assert data == original
    assert export(data=list(reversed(data)))[0] == queries
    (query,), _ = export(data={"Event": {"Attribute": [attribute()]}, "Attribute": [attribute(value="sibling.test")]})
    assert 'dynamic(["example.org", "sibling.test"])' in query


@pytest.mark.parametrize(
    "kind,value",
    [
        ("sha256", "x" * 64),
        ("md5", "a" * 31),
        ("sha1", "a' or true"),
        ("domain", "example.org' or true"),
        ("domain", "a..org"),
        ("domain", "*.example.org"),
        ("domain", "https://example.org/path"),
        ("ip-dst", "192.0.2.1/24"),
        ("ip-src", "fe80::1%eth0"),
        ("ip-src", "not-an-ip"),
        ("url", "example.org/path"),
        ("url", "https://example.org:99999/a"),
        ("url", "https://example.org/a\n| union DeviceEvents"),
        ("url", "https://example.org/\u2028x"),
        ("url", "https://example.org/\ud800"),
        ("domain", None),
        ("url", "https://example.org/" + "x" * 8192),
    ],
)
def test_invalid_values_are_skipped_without_exporting_unvalidated_text(kind, value):
    queries, summary = export([attribute(kind, value)])
    assert queries == [] and summary["skipped"] == {"invalid indicators": 1}


@pytest.mark.parametrize(
    "config",
    [{"Period": value} for value in ["7d) .. now()) or true //", "-1d", "0d", "31d", "1.5d", "7D", "1w", True, {}, []]]
    + [
        {"domain_mode": "contains"},
        {"domain_mode": False},
        {"tables": []},
        {"tables": False},
        {"start_time": False},
        {"end_time": False},
        {"tables": "DeviceAlertEvents"},
        {"tables": "DeviceNetworkEvents | take 1"},
        {"tables": ["AlertInfo"]},
        {"tables": [True]},
        {"tables": 2},
        *({"batch_size": value} for value in [True, 0, -1, 501, "1;union", 1.5]),
        {"start_time": "2026-01-01T00:00:00Z"},
        {"start_time": "2026-01-01T00:00:00", "end_time": "2026-01-02T00:00:00Z"},
        {"start_time": "2026-01-02T00:00:00Z", "end_time": "2026-01-01T00:00:00Z"},
        {"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-02-01T00:00:00Z"},
        {"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-02T00:00:00Z", "Period": "7d"},
    ],
)
def test_invalid_config_returns_an_error_with_no_partial_output(config):
    result = defender.handler(json.dumps({"data": [{"Attribute": [attribute()]}], "config": config}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize("period", ["1s", "60m", "720h", "30d"])
def test_valid_periods(period):
    (query,), _ = export([attribute()], {"Period": period})
    assert f"MISP_Start = ago({period});" in query


def test_absolute_times_are_validated_and_normalized_to_utc():
    (query,), _ = export(
        [attribute()], {"Period": "", "start_time": "2026-01-01T02:00:00+02:00", "end_time": "2026-01-02T00:00:00Z"}
    )
    assert "MISP_Start = datetime(2026-01-01T00:00:00+00:00);" in query
    assert "MISP_End = datetime(2026-01-02T00:00:00+00:00);" in query
    assert "ago(" not in query


def test_opt_in_tables_and_unmapped_indicators_are_reported():
    (query,), summary = export([attribute(), attribute("md5", "a" * 32)], {"tables": "EmailUrlInfo,UrlClickEvents"})
    assert "Device" not in query and "EmailUrlInfo" in query and "UrlClickEvents" in query
    assert summary["skipped"] == {"unmapped indicators": 1}
    assert "EmailUrlInfo" not in export([attribute()])[0][0]


def test_count_batches_are_independent_deterministic_and_deduplicate_before_splitting():
    attributes = [attribute(value=f"d{n}.example.org") for n in range(205)]
    queries, summary = export(attributes + attributes, {"batch_size": "100", "tables": "DeviceNetworkEvents"})
    assert summary == {"indicators": 205, "queries": 3, "skipped": {}}
    values = []
    for query in queries:
        assert query.startswith("let MISP_Start") and query.count("union withsource=") == 1
        batch = json.loads(re.search(r"MISP_domain = dynamic\((\[.*?\])\);", query)[1])
        assert 1 <= len(batch) <= 100
        values.extend(batch)
    assert len(set(values)) == 205
    assert export(list(reversed(attributes)), {"batch_size": 100, "tables": "DeviceNetworkEvents"})[0] == queries


def test_queries_split_by_utf8_bytes_without_dropping_values():
    attributes = [attribute("url", "https://example.org/" + str(n) + "é" * 3000) for n in range(12)]
    queries, summary = export(attributes, {"batch_size": 500})
    assert len(queries) > 1 and summary["indicators"] == 12
    values = []
    for query in queries:
        assert len(query.encode("utf-8")) <= 65536
        values.extend(json.loads(re.search(r"MISP_url = dynamic\((\[.*?\])\);", query)[1]))
    assert set(values) == {item["value"] for item in attributes}


def test_total_limit_is_atomic(monkeypatch):
    monkeypatch.setattr(defender, "MAX_INDICATORS", 2)
    result = defender.handler(json.dumps({"data": {"Attribute": [attribute(value=f"d{n}.test") for n in range(3)]}}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {},
        {"data": [], "config": None},
        {"data": [1]},
        {"data": {"Event": 1}},
        {"data": {"Attribute": {}}},
        {"data": {"Object": [1]}},
        {"data": {"Attribute": [attribute(deleted="maybe")]}},
    ],
)
def test_malformed_requests_return_an_error(payload):
    result = defender.handler(json.dumps(payload))
    assert "error" in result and "data" not in result


def test_protocol_empty_and_invalid_json():
    assert defender.handler() is False
    assert "error" in defender.handler("{")
    assert export()[0] == []
    assert defender.introspection()["outputFileExtension"] == "kql"


class TestDefenderExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous_handlers = service.MODULES_HANDLERS.copy()
        self.previous_cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"defender_endpoint_export": defender, "type:defender_endpoint_export": "export_mod"}
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous_handlers)
        service.ListModules.CACHE = self.previous_cache
        super().tearDown()

    def test_discovery_query_and_invalid_period(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["meta"]["config"] == defender.moduleconfig
        for config in ({"Period": "7d"}, {"Period": "invalid"}):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {"module": "defender_endpoint_export", "data": [{"Attribute": [attribute()]}], "config": config}
                ),
            )
            assert response.code == 200
            result = json.loads(response.body)
            if config["Period"] == "7d":
                assert "DeviceNetworkEvents" in base64.b64decode(result["data"]).decode()
            else:
                assert "error" in result and "data" not in result


def test_all_selected_field_mappings_are_valid_in_the_independent_schema_snapshot():
    for table, mappings in defender.TABLE_FIELDS.items():
        assert SCHEMAS[table]["columns"]["Timestamp"] == "datetime"
        for fields in mappings.values():
            assert all(SCHEMAS[table]["columns"][field] == "string" for field in fields)


def test_single_oversized_query_is_an_atomic_error(monkeypatch):
    monkeypatch.setattr(defender, "MAX_QUERY_BYTES", 100)
    result = defender.handler(json.dumps({"data": {"Attribute": [attribute()]}}))
    assert "error" in result and "data" not in result


def test_domain_scheme_detection_is_anchored_to_avoid_query_string_false_negatives():
    (query,), _ = export([attribute()])
    assert 'value matches regex @"^[A-Za-z][A-Za-z0-9+.-]*://"' in query
    assert 'value contains "://"' not in query
