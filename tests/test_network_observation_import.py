import base64
import copy
import hashlib
import json
import socket
from decimal import Decimal
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import network_observation as shared
from misp_modules.modules.import_mod import suricata_import as suricata
from misp_modules.modules.import_mod import zeek_import as zeek

FIXTURES = Path(__file__).parent / "fixtures/network_observation"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
ZEEK_FILES = sorted(p.name for p in FIXTURES.glob("zeek-*"))


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(filename="suricata-eve.jsonl", raw=None, config=None):
    module = zeek if filename.startswith("zeek-") else suricata
    raw = (FIXTURES / filename).read_bytes() if raw is None else raw
    if config is None:
        config = {
            "capture_file": MANIFEST["capture_file"],
            "capture_sha256": MANIFEST["capture_sha256"],
            "sensor": "fixture-sensor",
            "tool_version": "9.0.1" if module is zeek else "8.0.8",
        }
        if module is zeek:
            config["log_type"] = filename.split("-")[1].split(".")[0]
    result = module.handler(request(raw, config, filename=filename))
    assert "error" not in result, result
    return result


def objects(result, name="network-observation"):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def refs(obj, relationship):
    return [r["referenced_uuid"] for r in obj.get("ObjectReference", []) if r["relationship_type"] == relationship]


def eve(**kwargs):
    return {
        "timestamp": "2026-10-10T12:00:00.123456+0000",
        "event_type": "alert",
        "flow_id": 2**63 + 123,
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "src_port": 12345,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature_id": 1000001,
            "gid": 1,
            "rev": 1,
            "signature": "Synthetic observation",
            "severity": 3,
            "action": "allowed",
        },
        **kwargs,
    }


def conn(**kwargs):
    return {
        "ts": Decimal("1791633600.123456"),
        "uid": "Cfixture",
        "id.orig_h": "192.0.2.1",
        "id.resp_h": "198.51.100.2",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
        **kwargs,
    }


@pytest.mark.parametrize("filename", ZEEK_FILES + ["suricata-eve.jsonl"])
def test_actual_native_logs_preserve_capture_provenance_original_bytes_and_non_ids(filename):
    result = imported(filename)
    raw = (FIXTURES / filename).read_bytes()
    source = objects(result, "file")[0]
    capture = objects(result, "pcap-metadata")[0]
    assert fields(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(next(a["data"] for a in source["Attribute"] if a["object_relation"] == "attachment")) == raw
    assert fields(capture)["file-hash-sha256"] == MANIFEST["capture_sha256"] != fields(source)["sha256"]
    assert refs(capture, "derived-from") == [source["uuid"], *[o["uuid"] for o in objects(result)]]
    assert set(refs(source, "derived-from")) == {o["uuid"] for o in objects(result)}
    for obj in objects(result):
        values = fields(obj)
        assert (
            values["capture-file"] == MANIFEST["capture_file"]
            and values["capture-sha256"] == MANIFEST["capture_sha256"]
        )
        assert values["source-sha256"] == fields(source)["sha256"] and values["sensor"] == "fixture-sensor"
        assert values["event-time"].endswith("+00:00") and values["review-status"] == "unreviewed"
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    assert not result["warnings"]


def test_native_community_ids_match_across_tools_without_merging_records():
    json_result, tsv_result, eve_result = imported("zeek-conn.jsonl"), imported("zeek-conn.log"), imported()
    zeek_ids = {fields(o)["community-id"] for o in objects(json_result)}
    assert zeek_ids == {fields(o)["community-id"] for o in objects(tsv_result)}
    assert zeek_ids <= {fields(o)["community-id"] for o in objects(eve_result) if "community-id" in fields(o)}
    observations = objects(eve_result)
    assert len({o["uuid"] for o in observations}) == len(observations)
    assert len(objects(eve_result, "network-connection")) > len(zeek_ids)


def test_native_alert_retains_signature_ids_and_packet_reference_without_verdict_or_rule_body():
    result = imported(config={"event_types": "alert"})
    value = fields(objects(result)[0])
    assert value["signature-id"] == "1000001" and value["generator-id"] == value["signature-revision"] == "1"
    assert value["signature"] == "Synthetic MISP fixture HTTP observation" and value["severity"] == "3"
    assert value["action"] == "allowed" and value["packet-number"] == "6" and value["transaction-id"] == "0"
    assert (
        value["review-status"] == "unreviewed"
        and not objects(result, "suricata")
        and not objects(result, "threat-hunt-finding")
    )
    assert json.loads(value["raw-record"])["http"]["hostname"] == "example.test"


def test_zeek_notice_and_protocol_data_remain_source_observations():
    result = imported("zeek-notice.jsonl")
    values = fields(objects(result)[0])
    assert values["notice-type"] == "Fixture::HTTP_Observed" and values["message"] == "Synthetic HTTP observation"
    assert "signature-id" not in values
    for filename, key in [("zeek-dns.jsonl", "query"), ("zeek-http.jsonl", "uri")]:
        result = imported(filename)
        assert key in json.loads(fields(objects(result)[0])["raw-record"])
        assert all("first-packet-seen" not in fields(c) for c in objects(result, "network-connection"))


def test_conn_timestamp_is_start_while_json_duration_is_not_rounded_into_an_end():
    result = imported("zeek-conn.jsonl")
    source = [shared.loads(line) for line in (FIXTURES / "zeek-conn.jsonl").read_text().splitlines()]
    for obj, row in zip(objects(result), source):
        values = fields(obj)
        assert values["timestamp-raw"] == str(row["ts"])
        assert shared.loads(values["raw-record"])["duration"] == row["duration"]
        assert values["flow-start"] == values["event-time"] and "flow-end" not in values
    assert all(
        "first-packet-seen" in fields(c) and "last-packet-seen" not in fields(c)
        for c in objects(result, "network-connection")
    )


def test_selection_preserves_record_ordinals_without_leaking_excluded_record_attachment():
    rows = [json.loads(line) for line in (FIXTURES / "suricata-eve.jsonl").read_text().splitlines()]
    result = imported(config={"event_types": ["alert"]})
    assert result["summary"]["excluded"] == len(rows) - 1 and result["summary"]["imported"] == 1
    assert "attachment" not in fields(objects(result, "file")[0])
    assert '"stats"' not in json.dumps(result)
    native = [shared.loads(line) for line in (FIXTURES / "zeek-conn.jsonl").read_text().splitlines()]
    result = imported("zeek-conn.jsonl", config={"log_type": "conn", "uids": [native[1]["uid"]]})
    assert fields(objects(result)[0])["record-index"] == "2" and native[0]["uid"] not in json.dumps(result)
    assert "attachment" not in fields(objects(result, "file")[0])
    assert result["warnings"]


def test_flow_id_selection_handles_uint64_without_float_precision_loss():
    records = [eve(), eve(flow_id=2**63 + 124)]
    result = imported(raw=json.dumps(records).encode(), config={"flow_ids": str(2**63 + 124)})
    assert fields(objects(result)[0])["flow-id"] == str(2**63 + 124)
    assert result["summary"]["excluded"] == 1 and "attachment" not in fields(objects(result, "file")[0])


@pytest.mark.parametrize(
    "column,location,relation,value",
    [
        ("flow_id", None, "flow-id", -1),
        ("flow_id", None, "flow-id", 2**64),
        ("flow_id", None, "flow-id", 1.5),
        ("pcap_cnt", None, "packet-number", True),
        ("tx_id", None, "transaction-id", -1),
        ("signature_id", "alert", "signature-id", -1),
        ("gid", "alert", "generator-id", 2**32),
        ("rev", "alert", "signature-revision", 1.5),
        ("severity", "alert", "severity", True),
    ],
)
def test_corrupt_sensor_identifiers_are_not_promoted(column, location, relation, value):
    row = eve()
    (row[location] if location else row)[column] = value
    result = imported(raw=json.dumps(row).encode(), config={})
    fields_ = fields(objects(result)[0])
    assert relation not in fields_
    raw = json.loads(fields_["raw-record"])
    assert (raw[location] if location else raw)[column] == value and result["warnings"]


def test_capture_hash_is_not_reassigned_to_a_different_native_capture():
    row = eve(pcap_filename="other.pcap")
    config = {"capture_file": "default.pcap", "capture_sha256": "a" * 64, "capture_url": "https://example.test/default"}
    result = imported(raw=json.dumps(row).encode(), config=config)
    values = fields(objects(result)[0])
    assert values["capture-file"] == "other.pcap" and "capture-sha256" not in values and "capture-url" not in values
    assert "file-hash-sha256" not in fields(objects(result, "pcap-metadata")[0]) and result["warnings"]
    result = imported(raw=json.dumps(row).encode(), config={"capture_sha256": "a" * 64})
    assert "capture-sha256" not in fields(objects(result)[0])


def test_flow_bounds_are_explicit_and_inconsistent_bounds_remain_raw_only():
    row = eve(flow={"start": "2026-10-10T12:00:00.000001+0000", "end": "2026-10-10T12:00:01+0000"})
    result = imported(raw=json.dumps(row).encode(), config={})
    assert fields(objects(result)[0])["event-time"].endswith(".123456+00:00")
    assert fields(objects(result, "network-connection")[0])["first-packet-seen"].endswith(".000001+00:00")
    row["flow"]["end"] = "2020-01-01T00:00:00Z"
    result = imported(raw=json.dumps(row).encode(), config={})
    assert not {"flow-start", "flow-end"}.intersection(fields(objects(result)[0]))
    assert not {"first-packet-seen", "last-packet-seen"}.intersection(fields(objects(result, "network-connection")[0]))
    assert result["warnings"]


@pytest.mark.parametrize(
    "stamp", ["2026-10-10T12:00:00", "2026-10-10T12:00:00-0000", "2026-10-10T12:00:00.1234567Z", 123456]
)
def test_suricata_ambiguous_times_are_retained_without_normalization(stamp):
    result = imported(raw=json.dumps(eve(timestamp=stamp)).encode(), config={})
    values = fields(objects(result)[0])
    assert "event-time" not in values and "timestamp-raw" in values and result["warnings"]


@pytest.mark.parametrize(
    "stamp,unit,expected",
    [
        (Decimal("0"), "s", "1970-01-01T00:00:00+00:00"),
        (Decimal("-0.000001"), "s", "1969-12-31T23:59:59.999999+00:00"),
        (Decimal("1791633600123.456"), "ms", "2026-10-10T12:00:00.123456+00:00"),
        (1791633600123456, "us", "2026-10-10T12:00:00.123456+00:00"),
        (1791633600123456000, "ns", "2026-10-10T12:00:00.123456+00:00"),
    ],
)
def test_zeek_decimal_epochs_use_declared_units_without_float_rounding(stamp, unit, expected):
    result = imported(
        "zeek-conn.jsonl",
        raw=shared.dumps(conn(ts=stamp)).encode(),
        config={"log_type": "conn", "timestamp_unit": unit},
    )
    assert fields(objects(result)[0])["event-time"] == expected


@pytest.mark.parametrize("stamp", [Decimal("1791633600.1234567"), Decimal("1e999999"), Decimal("1e-999999"), True])
def test_zeek_submicrosecond_and_extreme_epochs_are_raw_only(stamp):
    raw = shared.dumps(conn(ts=stamp)).encode()
    result = imported("zeek-conn.jsonl", raw=raw, config={"log_type": "conn"})
    value = fields(objects(result)[0])
    assert "event-time" not in value and result["warnings"]
    assert shared.dumps(stamp) in value["raw-record"]


def test_zeek_tsv_escape_unset_empty_and_container_semantics_survive_selection():
    text = (
        "#separator"
        " \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tnotice\n#fields\tts\tuid\tmsg\ttags\tempty\tunset\tliteral\tflag\n#types\ttime\tstring\tstring\tset[string]\tstring\tstring\tstring\tbool\n1.000001\tCfixture\tone\\x09two\\x5cthree\tone\\x2ctwo,three\t(empty)\t-\t\\x2d\tT\n"
    )
    result = imported("zeek-notice.log", raw=text.encode(), config={})
    values = fields(objects(result)[0])
    raw = json.loads(values["raw-record"])
    assert values["message"] == "one\ttwo\\three"
    assert raw["decoded"]["tags"] == ["one,two", "three"]
    assert raw["decoded"]["empty"] == "" and raw["decoded"]["unset"] is None and raw["decoded"]["literal"] == "-"
    assert raw["decoded"]["flag"] is True and raw["headers"]["unset_field"] == "-"
    assert raw["columns"]["literal"] == "\\x2d"


@pytest.mark.parametrize("community", ["bogus", "2:unknown", False, {"bad": "id"}])
def test_invalid_community_ids_are_not_promoted(community):
    result = imported(raw=json.dumps(eve(community_id=community)).encode(), config={})
    values = fields(objects(result)[0])
    assert "community-id" not in values and "community-id-raw" in values and result["warnings"]
    assert "community-id" not in fields(objects(result, "network-connection")[0])


def test_invalid_endpoints_are_raw_only_and_valid_zero_ports_and_ipv6_survive():
    row = eve(src_ip="::1", dest_ip="2001:db8::1", src_port=0, dest_port=65535)
    result = imported(raw=json.dumps(row).encode(), config={})
    value = fields(objects(result, "network-connection")[0])
    assert value["ip-src"] == "::1" and value["src-port"] == "0" and value["dst-port"] == "65535"
    row.update(src_ip="bad", dest_ip=[], src_port=-1, dest_port=65536)
    result = imported(raw=json.dumps(row).encode(), config={})
    assert not objects(result, "network-connection") and result["warnings"]


def test_collector_wrapper_and_explicit_stream_context_are_enforced():
    wrapper = {"metadata": {"log_type": "conn", "sensor": "collector"}, "records": [conn()]}
    result = imported("zeek-conn.jsonl", raw=shared.dumps(wrapper).encode(), config={})
    assert fields(objects(result)[0])["sensor"] == "collector"
    assert "error" in zeek.handler(request(shared.dumps(conn()).encode(), {}))
    assert "error" in zeek.handler(request(shared.dumps(wrapper).encode(), {"sensor": "other"}))
    row = conn(_path="ssl", server_name="example.test")
    result = imported("zeek-conn.jsonl", raw=shared.dumps(row).encode(), config={})
    assert fields(objects(result)[0])["log-type"] == "ssl"
    assert "first-packet-seen" not in fields(objects(result, "network-connection")[0])


@pytest.mark.parametrize(
    "module,raw,config",
    [
        (zeek, b"[]", {}),
        (suricata, b'{"event_type":"alert","event_type":"flow"}', {}),
        (suricata, b'{"timestamp":NaN}', {}),
        (suricata, b'{"event_type":"alert"}', {}),
        (suricata, json.dumps(eve(alert=[])).encode(), {}),
        (suricata, json.dumps(eve(flow=None)).encode(), {}),
        (suricata, json.dumps(eve()).encode(), {"format": False}),
        (suricata, json.dumps(eve()).encode(), {"flow_ids": [True]}),
        (suricata, json.dumps(eve()).encode(), {"event_types": []}),
        (suricata, json.dumps(eve()).encode(), {"capture_sha256": "bad"}),
        (zeek, b"#fields\tts\tuid\n1\ta\n", {}),
    ],
)
def test_malformed_requests_are_atomic(module, raw, config):
    result = module.handler(request(raw, config))
    assert "error" in result and "results" not in result


def test_explicit_json_does_not_fall_back_and_tsv_schema_conflicts_are_errors():
    raw = (FIXTURES / "zeek-conn.jsonl").read_bytes()
    assert "error" in zeek.handler(request(raw, {"format": "json", "log_type": "conn"}))
    raw = (FIXTURES / "zeek-conn.log").read_bytes()
    for config in [{"log_type": "dns"}, {"timestamp_unit": "ms"}]:
        assert "error" in zeek.handler(request(raw, config))
    text = raw.decode().replace("\tid.orig_p\t", "\tuid\t", 1)
    assert "error" in zeek.handler(request(text.encode(), {}))


def test_limits_no_selection_and_bad_requests():
    assert "error" in suricata.handler(request(json.dumps([eve()] * 1001).encode(), {}))
    assert "error" in suricata.handler(request(json.dumps(eve()).encode(), {"event_types": "none"}))
    for module in (zeek, suricata):
        for q in ["null", "[]", "{}", json.dumps({"data": "%%%"}), request(b"\xff")]:
            assert "error" in module.handler(q)


def test_strict_templates_repeatability_and_no_network_or_capture_reads(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Importer must not access the network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    result = imported(config={"capture_file": "/nonexistent/capture.pcap", "capture_sha256": "b" * 64})
    assert result == imported(config={"capture_file": "/nonexistent/capture.pcap", "capture_sha256": "b" * 64})
    for obj in result["results"]["Object"]:
        custom = {"misp_objects_template_custom": shared._template()} if obj["name"] == "network-observation" else {}
        parsed = MISPObject(obj["name"], strict=True, **custom)
        parsed.from_dict(**copy.deepcopy(obj))
        assert parsed.to_json(strict=True)


class TestNetworkObservationHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "zeek_import": zeek,
                "type:zeek_import": "import_mod",
                "suricata_import": suricata,
                "type:suricata_import": "import_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_both_importers_and_errors(self):
        modules = {m["name"]: m for m in json.loads(self.fetch("/modules").body)}
        assert set(modules) == {"zeek_import", "suricata_import"}
        assert all(m["mispattributes"]["format"] == "misp_standard" for m in modules.values())
        for name, module, filename, config in [
            ("zeek_import", zeek, "zeek-conn.log", {}),
            ("suricata_import", suricata, "suricata-eve.jsonl", {"event_types": "alert"}),
        ]:
            assert module.handler() is False
            response = self.fetch(
                "/query", method="POST", body=request((FIXTURES / filename).read_bytes(), config, module=name)
            )
            assert response.code == 200 and objects(json.loads(response.body))
            response = self.fetch("/query", method="POST", body=json.dumps({"module": name, "data": "%%%"}))
            assert response.code == 200 and "error" in json.loads(response.body)
