import base64
import copy
import gzip
import hashlib
import json

import pytest
from pymisp import MISPObject
from pymisp.exceptions import InvalidMISPObject

from misp_modules.modules.import_mod import okta_system_log_import as module

EVENT_IDS = [
    "06632651-d2ba-11e5-a4c9-319ed15f8a76",
    "b5716c16-56c3-4d0a-8392-f0d34122f77f",
    "9673d3d3-27b1-4db1-998d-71b58ae0ea11",
    "4969b36d-d801-4604-8d75-772fec57255c",
]


def log_event(index=0):
    return {
        "uuid": EVENT_IDS[index],
        "published": "2026-11-22T16:35:12.123456789+01:00",
        "eventType": "user.session.start",
        "version": 0,
        "displayMessage": "User login to Okta",
        "severity": "INFO",
        "actor": {
            "id": "00u-example-person",
            "type": "User",
            "alternateId": "analyst@example.test",
            "displayName": "Example Analyst",
        },
        "client": {
            "ipAddress": "2001:0db8::5",
            "device": "Computer",
            "userAgent": {"rawUserAgent": "Example Browser"},
        },
        "transaction": {"id": "transaction-1", "type": "WEB", "detail": {"unmapped": "not-projected"}},
        "authenticationContext": {
            "authenticationProvider": "OKTA",
            "credentialType": "PASSWORD",
            "credentialProvider": "OKTA",
            "authenticationStep": 0,
            "externalSessionId": "session-1",
            "rootSessionId": "root-session",
        },
        "outcome": {"result": "SUCCESS", "reason": None},
        "debugContext": {"debugData": {"requestId": "request-1", "unmapped": "not-projected"}},
        "target": [
            {"id": "0oa-example-app", "type": "AppInstance", "displayName": "Example Cloud"},
            {
                "id": "00g-example-group",
                "type": "UserGroup",
                "displayName": "Example Group",
                "alternateId": "External Group",
            },
        ],
    }


def query_bytes(raw, **options):
    return module.handler(json.dumps({"data": base64.b64encode(raw).decode(), **options}))


def query(document, **options):
    return query_bytes(json.dumps(document).encode(), **options)


def grouped(result):
    assert "error" not in result, result
    all_objects = result["results"]["Object"]
    assert all_objects[0]["name"] == "file"
    uuids = {obj["uuid"] for obj in all_objects}
    assert len(uuids) == len(all_objects)
    by_name = {}
    for obj in all_objects:
        name = obj["name"]
        by_name.setdefault(name, []).append(obj)
        options = {} if name == "file" else {"misp_objects_template_custom": module._template(name)}
        rebuilt = MISPObject(name, strict=True, standalone=False, **options)
        rebuilt.from_dict(**obj)
        assert json.loads(rebuilt.to_json(strict=True))["uuid"] == obj["uuid"]
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert all(ref["referenced_uuid"] in uuids for ref in obj.get("ObjectReference", []))
    return by_name


def attrs(obj):
    return {item["object_relation"]: item for item in obj["Attribute"]}


def fields(obj):
    return {relation: attr["value"] for relation, attr in attrs(obj).items()}


def links(obj, kind):
    return [r for r in obj.get("ObjectReference", []) if r["relationship_type"] == kind]


def test_native_event_preserves_actor_target_and_authentication_context():
    entry = log_event()
    response = query(entry)
    result = grouped(response)
    (source,) = result["file"]
    (event,) = result[module.EVENT]
    targets = result[module.TARGET]
    values = fields(event)
    assert response["summary"]["format"] == "system-log-event"
    assert values["event-id"] == entry["uuid"] and values["event-type"] == "user.session.start"
    assert values["schema-version"] == "0" and values["authentication-step"] == "0"
    assert values["actor-id"] == "00u-example-person" and values["actor-alternate-id"] == "analyst@example.test"
    assert values["client-address"] == "2001:0db8::5" and values["client-ip"] == "2001:db8::5"
    assert values["transaction-id"] == "transaction-1" and values["external-session-id"] == "session-1"
    assert values["root-session-id"] == "root-session" and values["credential-type"] == "PASSWORD"
    assert values["published"] == "2026-11-22T15:35:12.123456+00:00" and values["published-raw"] == entry["published"]
    assert event["first_seen"] == event["last_seen"]
    assert values["outcome"] == "SUCCESS" and values["request-id"] == "request-1"
    assert links(event, "extracted-from")[0]["referenced_uuid"] == source["uuid"]
    assert [r["comment"] for r in links(event, "contains")] == ["target[0]", "target[1]"]
    assert [r["referenced_uuid"] for r in links(event, "contains")] == [o["uuid"] for o in targets]
    assert fields(targets[0]) == {
        "target-index": "1",
        "target-id": "0oa-example-app",
        "target-type": "AppInstance",
        "target-display-name": "Example Cloud",
    }
    assert fields(targets[1])["target-alternate-id"] == "External Group"
    assert attrs(event)["actor-id"]["disable_correlation"] is False
    assert attrs(targets[0])["target-id"]["disable_correlation"] is False
    assert attrs(event)["client-ip"]["disable_correlation"] is False
    assert attrs(event)["actor-alternate-id"]["disable_correlation"] is True
    assert "not-projected" not in json.dumps(response)
    assert "attachment" not in fields(source)


def test_native_target_template_requires_a_reported_field():
    target = MISPObject(module.TARGET, strict=True, misp_objects_template_custom=module._template(module.TARGET))
    target.add_attribute("target-index", value=1)
    with pytest.raises(InvalidMISPObject):
        target.to_json(strict=True)


def test_empty_targets_are_reported_and_retained_target_indices_stay_native():
    event = log_event()
    app = event["target"][0]
    event["target"] = [
        {},
        app,
        {"type": "", "id": None, "alternateId": "  ", "displayName": "\t"},
        {"type": "User"},
        {"detailEntry": {"example": "unmapped"}},
    ]
    second = log_event(1)
    second["target"] = [{}]
    response = query([event, second])
    result = grouped(response)
    first_event, second_event = result[module.EVENT]
    assert response["summary"]["events"] == 2 and response["summary"]["targets"] == 2
    assert response["summary"]["skipped_empty_targets"] == 4
    assert any("without reported identifying fields (4)" in message for message in response["warnings"])
    assert [r["comment"] for r in links(first_event, "contains")] == ["target[1]", "target[3]"]
    assert not links(second_event, "contains")
    assert [fields(o)["target-index"] for o in result[module.TARGET]] == ["2", "4"]
    assert fields(result[module.TARGET][1])["target-type"] == "User"


def test_shared_context_links_session_mfa_application_and_admin():
    login = log_event()
    mfa = log_event(1)
    mfa["eventType"] = "user.authentication.auth_via_mfa"
    mfa["authenticationContext"].update(credentialType="OTP", authenticationStep=1)
    mfa["debugContext"]["debugData"]["factorType"] = "token:software:totp"

    access = log_event(2)
    access["eventType"] = "user.authentication.sso"
    access["actor"]["id"] = "different-person"
    access["client"]["ipAddress"] = "192.0.2.23"
    access["authenticationContext"]["externalSessionId"] = "session-2"
    access["transaction"]["id"] = "transaction-2"

    admin = log_event(3)
    admin["eventType"] = "user.account.lock"
    admin["actor"]["id"] = "Okta#System"
    admin["client"]["ipAddress"] = "0.0.0.0"
    admin["transaction"]["id"] = "transaction-3"
    admin["authenticationContext"] = {"externalSessionId": "unknown"}
    admin["target"] = [{"id": "00u-example-person", "type": "User"}]

    payload = [login, mfa, access, admin]
    response = query(payload)
    result = grouped(response)
    first, second, third, fourth = result[module.EVENT]
    assert response["summary"]["related_event_links"] == 3
    assert not links(first, "related-to")
    for event in (second, third, fourth):
        (link,) = links(event, "related-to")
        assert link["referenced_uuid"] == first["uuid"]
    note = links(second, "related-to")[0]["comment"]
    assert all(label in note for label in ("external session ID", "root session ID", "client IP", "transaction ID"))
    assert fields(second)["reported-factor-type"] == "token:software:totp"
    note = links(third, "related-to")[0]["comment"]
    assert note == "Shared reported Okta actor or target ID, root session ID"
    note = links(fourth, "related-to")[0]["comment"]
    assert note == "Shared reported Okta actor or target ID"
    for relation in ("actor-id", "client-ip", "external-session-id"):
        assert attrs(fourth)[relation]["disable_correlation"] is True
    assert query(payload)["results"] == response["results"]


def test_identifier_kinds_and_placeholders_do_not_form_links():
    before = log_event()
    after = log_event(1)
    for row, ip in ((before, "0.0.0.0"), (after, "::")):
        row["actor"] = {"id": "Unknown"}
        row["target"] = []
        row["client"] = {"ipAddress": ip}
        row["authenticationContext"] = {"rootSessionId": ""}
    before["transaction"] = {"id": "shared-string"}
    after["transaction"] = {"id": "unknown"}
    after["authenticationContext"]["externalSessionId"] = "shared-string"
    response = query([before, after])
    result = grouped(response)
    assert response["summary"]["related_event_links"] == 0
    assert all(not links(event, "related-to") for event in result[module.EVENT])


def test_saved_api_array_and_gzip_preserve_exact_upload():
    record = log_event()
    raw = gzip.compress(("\ufeff" + json.dumps([record, record])).encode())
    result = query_bytes(raw, filename=r"C:\evidence\okta.json.gz", config={"include_source": "1"})
    group = grouped(result)
    (source,) = group["file"]
    attachment = attrs(source)["attachment"]
    assert result["summary"]["format"] == "system-log-array"
    assert result["summary"]["duplicate_records"] == 1 and result["summary"]["events"] == 1
    assert fields(source)["filename"] == "okta.json.gz" and fields(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(attachment["data"]) == raw
    assert grouped(query(record))[module.EVENT][0]["uuid"] == group[module.EVENT][0]["uuid"]


def test_missing_time_and_null_context_keep_unresolved_event():
    record = {
        "uuid": "example-redacted-identifier",
        "eventType": "user.session.start",
        "authenticationContext": None,
        "target": [{"type": "User", "id": None}],
        "client": {"ipAddress": "private"},
        "outcome": {"result": "FAILURE", "reason": "Credentials rejected"},
    }
    response = query(record)
    result = grouped(response)
    (event,) = result[module.EVENT]
    values = fields(event)
    assert values["event-id"] == "example-redacted-identifier"
    assert values["outcome"] == "FAILURE" and values["outcome-reason"] == "Credentials rejected"
    assert values["client-address"] == "private" and "client-ip" not in values
    assert "published" not in values and "first_seen" not in event
    assert any("did not report a published timestamp" in w for w in response["warnings"])


def test_conflicting_repeat_fails_the_upload():
    entry = log_event()
    other = copy.deepcopy(entry)
    other["outcome"]["result"] = "FAILURE"
    response = query([entry, other])
    assert set(response) == {"error"}
    assert "Record 2" in response["error"] and "Conflicting records" in response["error"]


@pytest.mark.parametrize(
    "input_, failure",
    [
        (b"[]", "between 1 and 1,000"),
        (b'{"records":[]}', "native System Log"),
        (b'{"uuid":"a","uuid":"b","eventType":"user.session.start"}', "Duplicate JSON key"),
        (b'{"uuid":"a","eventType":"user.session.start","target":["User"]}', "target[0] must be an object"),
        (b'{"uuid":"a","eventType":"user.session.start","published":"2026-11-22T12:00:00"}', "offset-aware"),
        (
            b'{"uuid":"a","eventType":"user.session.start","authenticationContext":{"authenticationStep":false}}',
            "nonnegative int32",
        ),
        (b"\x1f\x8b", "UTF-8 JSON"),
    ],
)
def test_malformed_or_unrelated_uploads_fail(input_, failure):
    result = query_bytes(input_)
    assert set(result) == {"error"}
    assert failure in result["error"]


def test_record_and_target_limits(monkeypatch):
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "between 1 and 1,000" in query([log_event(), log_event(1)])["error"]
    monkeypatch.setattr(module, "MAX_RECORDS", 2)
    monkeypatch.setattr(module, "MAX_TARGETS", 3)
    assert "exceeds 2,000 targets" in query([log_event(), log_event(1)])["error"]
    assert "exceeds 2,000 targets" in query([dict(log_event(i), target=[{}, {}]) for i in range(2)])["error"]
    monkeypatch.setattr(module, "MAX_JSON", 3)
    assert "Decoded System Log" in query_bytes(gzip.compress(b'[{"uuid":"a"}]'))["error"]
