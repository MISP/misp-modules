import base64
import gzip
import hashlib
import ipaddress
import json

import pytest
from pymisp import MISPObject

from misp_modules.modules.import_mod import ocsf_import as module

FINGERPRINT = "A1" * 32
NETWORK = {
    "class_uid": 4001,
    "class_name": "Network Activity",
    "category_uid": 4,
    "activity_id": 6,
    "type_uid": 400106,
    "severity_id": 0,
    "status_id": 0,
    "time": 1752247584123,
    "start_time_at_source": "preserve only",
    "metadata": {
        "version": "1.5.0",
        "product": {"vendor_name": "AWS", "name": "Amazon VPC"},
        "uid": "producer-event",
        "logged_time": 1752247584567,
    },
    "src_endpoint": {"ip": "192.0.2.10", "hostname": "SOURCE.Example."},
    "dst_endpoint": {"ip": "2001:0db8:0000::5"},
    "observables": [
        {"name": "src_endpoint.ip", "type_id": 2, "value": "192.0.2.10"},
        {"name": "rule.url", "type_id": "6", "value": "https://example.test/notice"},
        {"name": "dns.answer", "type_id": 2, "value": "::ffff:192.0.2.22"},
        {"name": "extension.unknown_field", "type_id": 99, "value": "raw only"},
    ],
}
FINDING = {
    "class_uid": 2004,
    "finding_info": {"uid": "finding-1", "title": "Observed process start"},
    "time": 1723564700,
    "time_dt": "2024-08-13 17:58:20.123+02:00",
    "metadata": {"version": "1.9.0", "product": {"name": "Example EDR", "vendor_name": "Example"}},
    "evidences": [
        {
            "actor": {
                "user": {"name": "operator"},
                "process": {
                    "name": "reader",
                    "cmd_line": "/opt/reader --check",
                    "file": {
                        "name": "reader",
                        "path": "/opt/reader",
                        "hashes": [
                            {"algorithm_id": 3, "value": FINGERPRINT},
                            {"algorithm_id": 13, "value": "b" * 64},
                            {"algorithm_id": 4, "value": "a" * 64},
                        ],
                    },
                },
            }
        },
    ],
    "unmapped": {"dst_endpoint": {"ip": "198.51.100.40"}},
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def result(data, **request):
    return module.handler(json.dumps({"data": base64.b64encode(data).decode(), **request}))


def get_attrs(obj, relation):
    return [attr for attr in obj["Attribute"] if attr["object_relation"] == relation]


def value(obj, relation):
    (attr,) = get_attrs(obj, relation)
    return attr["value"]


def objects(result):
    assert "error" not in result, result
    source, *events = result["results"]["Object"]
    assert source["name"] == "file"
    for event in events:
        assert event["name"] == "ocsf-event"
        assert value(event, "source-sha256") == value(source, "sha256")
        (ref,) = event["ObjectReference"]
        assert ref["referenced_uuid"] == source["uuid"] and ref["relationship_type"] == "extracted-from"
        obj = MISPObject("ocsf-event", strict=True, misp_objects_template_custom=module._template())
        obj.from_dict(**event)
        assert json.loads(obj.to_json(strict=True))["uuid"] == event["uuid"]
        for attr in event["Attribute"]:
            assert attr["to_ids"] is False
            assert attr["disable_correlation"] == (attr["object_relation"] not in module.CORRELATABLE)
    return source, events


def test_gzip_json_lines_preserve_source_bytes_and_split_event_classes():
    first = json.dumps(NETWORK, separators=(", ", ": "))
    second = json.dumps(FINDING)
    payload = gzip.compress(("\ufeff" + first + "\r\n\n" + second + "\n").encode())
    imported = result(payload, filename=r"C:\Evidence\ocsf.jsonl.gz", config={"include_source": "1"})
    src, (network, finding) = objects(imported)
    assert imported["summary"]["format"] == "json-lines" and imported["summary"]["gzip"]
    assert value(src, "filename") == "ocsf.jsonl.gz"
    assert value(src, "sha256") == sha256(payload)
    assert base64.b64decode(get_attrs(src, "attachment")[0]["data"]) == payload
    assert value(network, "record-index") == "1" and value(finding, "record-index") == "2"
    assert value(network, "raw-event") == first
    assert value(finding, "event-sha256") == sha256(second.encode())
    assert value(network, "source-ip") == "192.0.2.10"
    source_ip = get_attrs(network, "source-ip")[0]
    assert "src_endpoint.ip" in source_ip["comment"]
    assert "observables[0].value" in source_ip["comment"]
    assert value(network, "destination-ip") == "2001:db8::5"
    assert ipaddress.ip_address(value(network, "ip-address")) == ipaddress.ip_address("::ffff:192.0.2.22")
    assert value(network, "hostname") == "source.example"
    assert value(network, "url") == "https://example.test/notice"
    assert value(network, "event-time") == "2025-07-11T15:26:24.123000+00:00"
    assert value(network, "logged-time") == "2025-07-11T15:26:24.567000+00:00"
    assert value(network, "status-id") == value(network, "severity-id") == "0"

    assert value(finding, "class-id") == "2004" and value(finding, "finding-id") == "finding-1"
    assert value(finding, "event-time") == "2024-08-13T15:58:20.123000+00:00"
    assert "disagreed" in get_attrs(finding, "event-time")[0]["comment"]
    assert any("time_dt disagrees" in warning for warning in imported["warnings"])
    assert value(finding, "process-name") == "reader" and value(finding, "user-name") == "operator"
    assert value(finding, "command-line") == "/opt/reader --check"
    assert value(finding, "file-path") == "/opt/reader"
    assert value(finding, "sha256") == FINGERPRINT.lower()
    assert value(finding, "sha3-256") == "b" * 64
    assert not get_attrs(finding, "sha512") and not get_attrs(finding, "destination-ip")


def test_array_accepts_extension_and_repeated_ids_preserving_ordinals():
    text = '{  "class_uid": "85010001", "metadata": {"uid": "shared"}, "time": 0, "numeric": 1.1234567890001 }'
    payload = f"[ {text}, {text} ]".encode()
    result_ = result(payload, filename="events.json")
    _, events = objects(result_)
    assert result_["summary"]["format"] == "json-array"
    assert result(payload, filename="events.json")["results"] == result_["results"]
    assert events[0]["uuid"] != events[1]["uuid"]
    for event in events:
        assert value(event, "class-id") == "85010001"
        assert value(event, "event-time") == "1970-01-01T00:00:00+00:00"
        assert value(event, "raw-event") == text
        assert value(event, "event-sha256") == sha256(text.encode())


def test_multiline_json_stream_and_neutral_observable_direction():
    event = dict(
        NETWORK,
        observables=[
            {"name": "dst_endpoint.intermediate_ips[]", "type_id": 2, "value": "192.0.2.30"},
        ],
    )
    first = json.dumps(event, indent=2)
    payload = (first + "\n\n" + json.dumps(FINDING)).encode()
    imported = result(payload)
    _, (network, _) = objects(imported)
    assert imported["summary"]["format"] == "json-stream"
    assert value(network, "raw-event") == first
    assert value(network, "ip-address") == "192.0.2.30"
    assert value(network, "destination-ip") == "2001:db8::5"


def test_large_unicode_event_preserves_whitespace_and_exact_text():
    record_text = json.dumps({"class_uid": 0, "unmapped": "🛰️ " + " x " * 13000}, ensure_ascii=False)
    _, (obj,) = objects(result(record_text.encode()))
    numbered = [json.loads(a["value"]) for a in get_attrs(obj, "raw-event-part")]
    assert len(numbered) > 1
    assert all(len(a["value"].encode()) < 60 * 1024 for a in get_attrs(obj, "raw-event-part"))
    assert all(chunk["parts"] == len(numbered) for chunk in numbered)
    assert "".join(chunk["text"] for chunk in sorted(numbered, key=lambda x: x["part"])) == record_text
    assert value(obj, "event-sha256") == sha256(record_text.encode())


def test_unsupported_pivots_and_unzoned_time_remain_in_source():
    source = {
        "class_uid": 1007,
        "time_dt": "2025-02-11T12:00:00",
        "time": True,
        "src_endpoint": {"ip": "fe80::1%en0"},
        "observables": [{"type_id": 6, "value": "https://name:secret@example.test"}],
    }
    response = result(json.dumps(source).encode())
    _, (record,) = objects(response)
    assert json.loads(value(record, "raw-event")) == source
    assert not get_attrs(record, "event-time") and not get_attrs(record, "url") and not get_attrs(record, "source-ip")
    assert any("Invalid time_dt" in w for w in response["warnings"])


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"{}", "class_uid"),
        (b'{"class_uid":true}', "class_uid"),
        (b'{"class_uid":1,"class_uid":2}', "Duplicate"),
        (b'{"class_uid":1,"details":NaN}', "Non-finite"),
        (b'{"class_uid":1}\n{"class_uid":2,}', "Record 2"),
        (b'{"class_uid":1} {"class_uid":2}', "newline"),
        (b'[{"class_uid":1},]', "Record 2"),
        (b'[{"class_uid":1}]x', "end of the JSON array"),
        (b"[]", "no OCSF events"),
        (b"PAR1mock", "Parquet"),
        (b"\x1f\x8b", "gzip-compressed"),
    ],
)
def test_malformed_or_unsupported_uploads_fail_as_a_batch(raw, error):
    response = result(raw)
    assert set(response) == {"error"}
    assert error in response["error"]


def test_hard_limits_and_pivot_budget(monkeypatch):
    monkeypatch.setattr(module, "MAX_JSON", 8)
    assert "Decompressed" in result(gzip.compress(b'{"class_uid":1}'))["error"]
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "exceeds" in result(b'[{"class_uid":1},{"class_uid":2}]')["error"]
    monkeypatch.setattr(module, "MAX_RECORD_BYTES", 20)
    assert "512 KiB" in result(json.dumps(NETWORK).encode())["error"]
    monkeypatch.setattr(module, "MAX_RECORD_BYTES", 65536)
    monkeypatch.setattr(module, "MAX_PIVOTS", 1)
    response = result(json.dumps(NETWORK).encode())
    _, (obj,) = objects(response)
    assert response["summary"]["projected_values"] == 1
    assert json.loads(value(obj, "raw-event")) == NETWORK
    assert any("distinct projected values" in w for w in response["warnings"])
