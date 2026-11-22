import base64
import copy
import gzip
import hashlib
import json

import pytest

from misp_modules.modules.import_mod import google_workspace_audit_import as importer


def activity(app="login", *, customer="C01example", qualifier="9223372036854775807"):
    return {
        "kind": "admin#reports#activity",
        "id": {
            "applicationName": app,
            "time": "2025-05-17T12:31:01.123456789+02:00",
            "uniqueQualifier": qualifier,
            "customerId": customer,
        },
        "actor": {"email": "alice@example.org", "profileId": "106432175044490301416", "callerType": "USER"},
        "ownerDomain": "example.org",
        "ipAddress": "2001:0db8::1",
        "events": [{"name": "login_success", "type": "login"}],
    }


def investigation():
    login = activity()
    login["events"][0]["parameters"] = [
        {"name": "login_type", "value": "google_password"},
        {"name": "is_suspicious", "boolValue": False},
    ]
    admin = activity("admin")
    admin["events"] = [
        {
            "type": "DELEGATED_ADMIN_SETTINGS",
            "name": "ASSIGN_ROLE",
            "parameters": [
                {"name": "USER_EMAIL", "value": "alice@example.org"},
                {"name": "ROLE_ID", "value": "123456"},
            ],
        }
    ]
    drive = activity("drive")
    drive["actor"]["applicationInfo"] = {"oauthClientId": "123.apps.googleusercontent.com"}
    drive["events"] = [
        {
            "type": "acl_change",
            "name": "change_user_access",
            "resourceIds": ["resource-1"],
            "status": {"eventStatus": "FAILED", "httpStatusCode": 403, "errorMessage": "Denied.\nTry again later."},
            "parameters": [
                {"name": "doc_id", "value": "file-123"},
                {"name": "target_user", "value": "reader@example.net"},
                {"name": "visibility", "value": "shared_externally"},
                {"name": "owner", "value": "Shared drive name"},
            ],
        }
    ]
    token = activity("token")
    token["events"] = [
        {
            "type": "auth",
            "name": "authorize",
            "parameters": [
                {"name": "client_id", "value": "123.apps.googleusercontent.com"},
                {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/drive", "openid"]},
            ],
        }
    ]
    return [login, admin, drive, token]


def submit(document, **fields):
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
    return importer.handler(json.dumps({"data": base64.b64encode(raw).decode("ascii"), **fields}))


def attributes(obj, relation):
    return [attr for attr in obj["Attribute"] if attr["object_relation"] == relation]


def values(obj, relation):
    return [attr["value"] for attr in attributes(obj, relation)]


def refs(obj, relationship):
    return [
        ref["referenced_uuid"] for ref in obj.get("ObjectReference", []) if ref["relationship_type"] == relationship
    ]


def test_cross_application_investigation():
    result = submit(investigation())
    source, login, admin, drive, token, sign_in, role, sharing, grant = result["results"]["Object"]
    assert result["summary"]["applications"] == dict.fromkeys(("login", "admin", "drive", "token"), 1)
    assert not attributes(source, "attachment")
    assert values(login, "ip-src") == ["2001:db8::1"]
    assert values(login, "source-address") == ["2001:0db8::1"]
    for parent, event in zip((login, admin, drive, token), (sign_in, role, sharing, grant), strict=True):
        assert parent["name"] == importer.ACTIVITY
        assert event["name"] == importer.EVENT
        assert refs(parent, "extracted-from") == [source["uuid"]]
        assert refs(parent, "contains") == [event["uuid"]]
        assert values(parent, "activity-qualifier") == ["9223372036854775807"]
        assert values(parent, "activity-time-raw") == ["2025-05-17T12:31:01.123456789+02:00"]
        assert values(parent, "activity-time") == ["2025-05-17T10:31:01.123456+00:00"]
        assert event["first_seen"] == parent["first_seen"] == parent["last_seen"]
        assert not attributes(parent, "actor-email")[0]["disable_correlation"]
        if parent is not login:
            assert refs(parent, "related-to") == [login["uuid"]]
    assert values(sign_in, "login-type") == ["google_password"]
    assert values(sign_in, "suspicious-login") == ["false"]
    assert values(role, "affected-user") == ["alice@example.org"]
    assert not attributes(role, "affected-user")[0]["disable_correlation"]
    assert values(role, "admin-role-id") == ["123456"]
    assert values(sharing, "sharing-target") == ["reader@example.net"]
    assert not attributes(sharing, "sharing-target")[0]["disable_correlation"]
    assert attributes(sharing, "document-owner")[0]["disable_correlation"]
    assert values(sharing, "resource-id") == ["resource-1"]
    assert values(sharing, "event-status") == ["FAILED"]
    assert values(sharing, "http-status-code") == ["403"]
    assert values(sharing, "error-message") == ["Denied.\nTry again later."]
    assert not attributes(sharing, "document-id")[0]["disable_correlation"]
    assert values(grant, "oauth-scope") == ["https://www.googleapis.com/auth/drive", "openid"]
    assert values(drive, "oauth-client-id") == values(grant, "oauth-client-id") == ["123.apps.googleusercontent.com"]
    assert not attributes(grant, "oauth-client-id")[0]["disable_correlation"]
    assert not any(attr["to_ids"] for obj in result["results"]["Object"] for attr in obj["Attribute"])


def test_event_ordinals_and_typed_parameter_evidence():
    parameters = [
        {"name": "shared_name", "intValue": "0"},
        {"name": "shared_name", "boolValue": False},
        {"name": "shared_name", "boolValue": False},
        {"name": "message", "messageValue": {"parameter": [{"name": "flag", "boolValue": False}]}},
        {"name": "multi", "multiMessageValue": [{"parameter": [{"name": "n", "multiIntValue": ["-1", "0"]}]}]},
    ]
    first = {"name": "login_challenge", "type": "login", "parameters": parameters}
    second = {"name": "login_challenge", "type": "login", "sensitiveParameters": [{"name": "opaque", "value": "a"}]}
    login = activity()
    login["events"] = [first, second]
    source, parent, child_one, child_two = submit(login)["results"]["Object"]
    assert refs(parent, "contains") == [child_one["uuid"], child_two["uuid"]]
    assert child_one["uuid"] != child_two["uuid"]
    assert values(child_one, "event-index") == ["1"]
    assert values(child_two, "event-index") == ["2"]
    assert values(child_one, "event-name") == values(child_two, "event-name") == ["login_challenge"]
    raw = attributes(child_one, "parameter")
    assert [item["comment"] for item in raw] == [f"parameters[{i}]" for i in range(len(parameters))]
    assert [json.loads(item["value"]) for item in raw] == parameters
    assert len({item["uuid"] for item in raw}) == len(parameters)
    assert all(item["disable_correlation"] for item in raw)
    (sensitive,) = attributes(child_two, "sensitive-parameter")
    assert json.loads(sensitive["value"]) == second["sensitiveParameters"][0]
    assert sensitive["comment"] == "sensitiveParameters[0]"
    assert sensitive["disable_correlation"]


def test_compound_id_keeps_nanoseconds_and_customer_and_deduplicates():
    same = activity()
    other_time = copy.deepcopy(same)
    other_time["id"]["time"] = "2025-05-17T12:31:01.123456788+02:00"
    records = [same, activity(customer="C02example"), other_time, copy.deepcopy(same)]
    result = submit(records)
    _, first, other_customer, different_time, *children = result["results"]["Object"]
    assert result["summary"]["duplicate_records"] == 1
    assert not refs(other_customer, "related-to")
    assert len({first["uuid"], other_customer["uuid"], different_time["uuid"]}) == 3
    assert len({child["uuid"] for child in children}) == 3
    assert values(first, "activity-time") == values(different_time, "activity-time")
    rerun = submit(same)["results"]["Object"]
    assert rerun[1]["uuid"] == first["uuid"]
    assert rerun[2]["uuid"] == children[0]["uuid"]
    conflicting = copy.deepcopy(same)
    conflicting["events"].append({"type": "login", "name": "login_challenge"})
    result = submit([same, conflicting])
    assert "Activity 2: Conflicting records share the same activity ID" in result["error"]
    assert "results" not in result


def test_actor_placeholders_are_retained_without_links_or_correlation():
    login, admin = activity(), activity("admin")
    for record in (login, admin):
        record["actor"] = {"profileId": importer.PLACEHOLDER_PROFILE, "email": "anonymous"}
        record["ipAddress"] = "REDACTED"
    _, *objects = submit([login, admin])["results"]["Object"]
    for obj in objects[:2]:
        assert attributes(obj, "actor-email")[0]["disable_correlation"]
        assert attributes(obj, "actor-profile-id")[0]["disable_correlation"]
        assert not refs(obj, "related-to")
        assert values(obj, "source-address") == ["REDACTED"]
        assert not attributes(obj, "ip-src")


def test_exact_gzip_source_and_pagination():
    raw = gzip.compress(
        b"\xef\xbb\xbf"
        + json.dumps(
            {"kind": "admin#reports#activities", "items": [activity()], "nextPageToken": "redact-this"}
        ).encode("utf-8")
    )
    result = submit(raw, filename="C:\\exports\\report.json.gz", config={"include_source": True})
    source, parent, _ = result["results"]["Object"]
    assert result["summary"]["has_next_page"] and result["summary"]["source_attached"]
    assert any("another page" in warning for warning in result["warnings"])
    assert "redact-this" not in json.dumps(result)
    assert refs(parent, "extracted-from") == [source["uuid"]]
    assert values(source, "filename") == ["report.json.gz"]
    assert values(source, "sha256") == [hashlib.sha256(raw).hexdigest()]
    assert values(source, "size-in-bytes") == [str(len(raw))]
    assert base64.b64decode(attributes(source, "attachment")[0]["data"]) == raw


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"kind": "admin#reports#activities"}, "contains no activities"),
        ({"kind": "admin#reports#activities", "nextPageToken": "token"}, "reports another page"),
        ({"kind": "admin#reports#activities", "items": {}}, "items must be an array"),
        (
            {"kind": "admin#reports#activities", "items": [activity()], "nextPageToken": 1},
            "nextPageToken must be a string",
        ),
        ({"kind": "unrelated", "items": [activity()]}, "Expected a Google Workspace activities.list response"),
        (activity("saml"), "id.applicationName must be login, admin, drive or token"),
        ({"id": {"applicationName": "login", "customerId": "C01example"}}, "id.uniqueQualifier"),
        (activity() | {"events": [42]}, "Activity 1: events[0]: event must be an object"),
        (activity() | {"events": [{"parameters": {"name": "p"}}]}, "parameters must be an array"),
        (b'{"items":[],"items":[]}', "Duplicate JSON key"),
    ],
)
def test_rejects_malformed_or_unrelated_input(document, message):
    result = submit(document)
    assert message in result["error"]
    assert "results" not in result


def test_enforces_parameter_budget(monkeypatch):
    monkeypatch.setattr(importer, "MAX_PARAMETER", 100)
    invalid = activity() | {"events": [{"parameters": [{"name": "p", "value": "a" * 100}]}]}
    assert "events[0]: parameters[0] exceeds" in submit(invalid)["error"]
