import base64
import copy
import gzip
import hashlib
import json

import pytest
from pymisp import MISPObject

from misp_modules.modules.import_mod import google_cloud_audit_import as module

EVENT = "google-cloud-audit-event"
CHECK = "google-cloud-authorization-check"
BINDING = "google-cloud-iam-binding-change"
CONDITION = {"title": "Limited access", "expression": 'resource.name.startsWith("projects/")\n&& true'}


def log_entry(category="activity", scope="projects/example-project", entry_id="entry-123"):
    return {
        "logName": f"{scope}/logs/cloudaudit.googleapis.com%2F{category}",
        "insertId": entry_id,
        "timestamp": "2026-11-21T15:30:00.123456789Z",
        "receiveTimestamp": "2026-11-21T16:30:01.001000004+01:00",
        "severity": "NOTICE",
        "resource": {"type": "project", "labels": {"project_id": "monitored-project"}},
        "operation": {"id": "operation-42", "producer": "cloudresourcemanager.googleapis.com"},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "methodName": "SetIamPolicy",
            "resourceName": "projects/example-project",
            "authenticationInfo": {
                "principalEmail": "service-account@example-project.iam.gserviceaccount.com",
                "principalSubject": "serviceAccount:service-account@example-project.iam.gserviceaccount.com",
                "serviceAccountDelegationInfo": [
                    {"firstPartyPrincipal": {"principalEmail": "analyst@example.test"}},
                    {"principalSubject": "principal://iam.googleapis.com/example"},
                ],
            },
            "requestMetadata": {"callerIp": "2001:0db8::1", "callerSuppliedUserAgent": "example-parser"},
            "status": {"code": 0},
            "authorizationInfo": [
                {
                    "resource": "projects/example-project",
                    "permission": "resourcemanager.projects.setIamPolicy",
                    "granted": True,
                },
                {
                    "resource": "projects/secondary-project",
                    "permission": "example.resources.read",
                    "permissionType": "DATA_READ",
                    "granted": False,
                    "resourceAttributes": {
                        "name": "objects/item",
                        "service": "example.googleapis.com",
                        "type": "Object",
                    },
                },
                {"permission": "resourcemanager.projects.get"},
            ],
            "metadata": {
                "policyDelta": {
                    "bindingDeltas": [
                        {
                            "action": "ADD",
                            "role": "roles/viewer",
                            "member": "user:added@example.test",
                            "condition": CONDITION,
                        }
                    ]
                }
            },
            "serviceData": {
                "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                "policyDelta": {
                    "bindingDeltas": [{"action": "REMOVE", "role": "roles/editor", "member": "user:old@example.test"}]
                },
            },
            "request": {"unmapped": "not-projected"},
        },
    }


def import_bytes(data, **opts):
    encoded = base64.b64encode(data).decode()
    return module.handler(json.dumps({"data": encoded, **opts}))


def run(document, **opts):
    return import_bytes(json.dumps(document).encode(), **opts)


def objects(result):
    assert "error" not in result, result
    result_objects = result["results"]["Object"]
    assert result_objects[0]["name"] == "file"
    uuids = {obj["uuid"] for obj in result_objects}
    assert len(uuids) == len(result_objects)
    grouped = {}
    for obj in result_objects:
        name = obj["name"]
        grouped.setdefault(name, []).append(obj)
        template = {} if name == "file" else {"misp_objects_template_custom": module._template(name)}
        parsed = MISPObject(name, strict=True, standalone=False, **template)
        parsed.from_dict(**obj)
        assert json.loads(parsed.to_json(strict=True))["uuid"] == obj["uuid"]
        assert all(attr["to_ids"] is False and attr["disable_correlation"] is True for attr in obj["Attribute"])
        assert all(ref["referenced_uuid"] in uuids for ref in obj.get("ObjectReference", []))
    return grouped


def fields(obj):
    return {attr["object_relation"]: attr["value"] for attr in obj["Attribute"]}


def test_native_event_keeps_grouped_policy_and_authorization_evidence():
    entry = log_entry()
    result = run(entry)
    grouped = objects(result)
    (source,) = grouped["file"]
    (event,) = grouped[EVENT]
    values = fields(event)
    assert result["summary"]["format"] == "log-entry"
    assert result["summary"]["authorization_checks"] == 3
    assert result["summary"]["iam_binding_changes"] == 2
    assert values["log-name"] == entry["logName"]
    assert values["scope-id"] == "example-project" and values["monitored-project-id"] == "monitored-project"
    assert values["event-time"] == "2026-11-21T15:30:00.123456+00:00"
    assert values["event-time-raw"] == entry["timestamp"]
    assert values["received-time"] == "2026-11-21T15:30:01.001000+00:00"
    assert values["received-time-raw"] == entry["receiveTimestamp"]
    assert event["first_seen"] == event["last_seen"]
    assert values["service-name"] == "cloudresourcemanager.googleapis.com"
    assert values["method-name"] == "SetIamPolicy"
    assert values["resource-name"] == "projects/example-project"
    assert values["principal-email"] == entry["protoPayload"]["authenticationInfo"]["principalEmail"]
    assert values["principal-subject"].startswith("serviceAccount:")
    assert values["caller-address"] == "2001:0db8::1" and values["source-ip"] == "2001:db8::1"
    assert values["status-code"] == "0"
    delegation = [a for a in event["Attribute"] if a["object_relation"] == "delegation-principal"]
    assert [json.loads(a["value"]) for a in delegation] == [
        {"principalEmail": "analyst@example.test"},
        {"principalSubject": "principal://iam.googleapis.com/example"},
    ]
    assert "serviceAccountDelegationInfo[1]" in delegation[1]["comment"]
    assert event["ObjectReference"][0]["referenced_uuid"] == source["uuid"]
    assert event["ObjectReference"][0]["comment"] == "Google Cloud LogEntry 1"
    assert "attachment" not in fields(source) and "not-projected" not in json.dumps(result)

    checks = [fields(obj) for obj in grouped[CHECK]]
    assert [c["decision"] for c in checks] == ["granted", "denied", "unknown"]
    assert checks[1] == {
        "decision": "denied",
        "permission": "example.resources.read",
        "resource-name": "projects/secondary-project",
        "permission-type": "DATA_READ",
        "resource-attribute-name": "objects/item",
        "resource-service": "example.googleapis.com",
        "resource-type": "Object",
    }
    assert event["ObjectReference"][2]["comment"] == "protoPayload.authorizationInfo[1]"
    added, removed = [fields(obj) for obj in grouped[BINDING]]
    assert added["action"] == "ADD" and added["role"] == "roles/viewer"
    assert json.loads(added["condition"]) == CONDITION
    assert removed == {"action": "REMOVE", "role": "roles/editor", "member": "user:old@example.test"}
    assert event["ObjectReference"][-1]["comment"] == "protoPayload.serviceData.policyDelta.bindingDeltas[0]"


def test_cli_array_covers_four_categories_and_preserves_native_scopes():
    entries = [
        log_entry("activity", "projects/example-project"),
        log_entry("data_access", "organizations/123"),
        log_entry("policy", "folders/456"),
        log_entry("system_event", "billingAccounts/AAAAAA-BBBBBB-CCCCCC"),
    ]
    policy = entries[2]["protoPayload"]
    policy["status"]["code"] = 7
    policy["requestMetadata"]["callerIp"] = "gce-internal-ip"
    policy["authenticationInfo"] = {}
    result = run(entries)
    events = [fields(e) for e in objects(result)[EVENT]]
    assert result["summary"]["categories"] == {"activity": 1, "data_access": 1, "policy": 1, "system_event": 1}
    assert events[2]["status-code"] == "7" and events[2]["caller-address"] == "gce-internal-ip"
    assert "principal-email" not in events[2] and "source-ip" not in events[2]
    assert events[3]["scope-type"] == "billingAccounts"
    assert len({e["scope-type"] for e in events}) == 4


def test_api_gzip_source_hash_and_pagination():
    response = {"entries": [log_entry()], "nextPageToken": "private-token"}
    raw = gzip.compress(("\ufeff" + json.dumps(response)).encode())
    result = import_bytes(raw, filename=r"C:\exports\page.json.gz", config={"include_source": "yes"})
    (source,) = objects(result)["file"]
    (attachment,) = (a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert fields(source)["filename"] == "page.json.gz"
    assert fields(source)["sha256"] == result["summary"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(attachment["data"]) == raw
    assert result["summary"]["has_next_page"] and result["summary"]["format"] == "logging-api"
    assert "private-token" not in json.dumps(result)
    assert any("another page" in warning for warning in result["warnings"])


def test_scoped_identity_preserves_sub_microseconds_and_repeated_idless_events():
    entry = log_entry()
    slightly_later = copy.deepcopy(entry)
    slightly_later["timestamp"] = "2026-11-21T15:30:00.123456790Z"
    idless = log_entry(entry_id=None)
    result = run([entry, slightly_later, entry, idless, idless])
    events = objects(result)[EVENT]
    assert result["summary"]["duplicate_records"] == 1 and len(events) == 4
    assert fields(events[0])["event-time"] == fields(events[1])["event-time"]
    assert events[0]["uuid"] != events[1]["uuid"]
    separate_page = objects(run({"entries": [entry]}))[EVENT][0]
    assert separate_page["uuid"] == events[0]["uuid"]
    assert separate_page["ObjectReference"][0]["referenced_uuid"] != events[0]["ObjectReference"][0]["referenced_uuid"]
    assert [r["uuid"] for r in events] == [
        r["uuid"] for r in objects(run([entry, slightly_later, entry, idless, idless]))[EVENT]
    ]


def test_missing_event_timestamp_preserves_reception_time_and_position():
    entry = log_entry()
    del entry["timestamp"]
    result = run([entry, entry])
    events = objects(result)[EVENT]
    assert len(events) == 2
    assert result["summary"]["duplicate_records"] == 0
    assert any("did not report an event timestamp" in w for w in result["warnings"])
    for event in events:
        values = fields(event)
        assert "event-time" not in values
        assert "first_seen" not in event and "last_seen" not in event
        assert values["received-time-raw"] == entry["receiveTimestamp"]


def test_status_without_code_and_unreported_permission_remain_unresolved():
    entry = log_entry()
    entry["protoPayload"].update(status={}, authorizationInfo=[{"permission": "examples.get"}])
    grouped = objects(run(entry))
    assert "status-code" not in fields(grouped[EVENT][0])
    assert fields(grouped[CHECK][0]) == {"permission": "examples.get", "decision": "unknown"}


@pytest.mark.parametrize(
    "override, expected",
    [
        ({"logName": "projects/proj/logs/other"}, "audit Logs category"),
        ({"protoPayload": {"@type": "type.googleapis.com/example.Event"}}, "google.cloud.audit.AuditLog"),
        ({"timestamp": "2026-11-21T15:30:00"}, "RFC 3339"),
        ({"timestamp": "2026-11-21T15:30:00.1234567890Z"}, "RFC 3339"),
    ],
)
def test_invalid_native_records_fail_batch(override, expected):
    response = run([log_entry(), dict(log_entry(entry_id="second"), **override)])
    assert set(response) == {"error"}
    assert "Record 2" in response["error"] and expected.lower() in response["error"].lower()


def test_rejects_conflicting_records_and_malformed_checks():
    conflicting = log_entry()
    conflicting["protoPayload"]["methodName"] = "GetIamPolicy"
    assert "Conflicting" in run([log_entry(), conflicting])["error"]
    malformed = log_entry()
    malformed["protoPayload"]["authorizationInfo"][0]["granted"] = "false"
    assert "granted must be a boolean" in run(malformed)["error"]


def test_unsupported_input_empty_api_page_and_limits(monkeypatch):
    assert "another page" in run({"nextPageToken": "private-token"})["error"]
    assert "no audit entries" in run([])["error"]
    assert "Duplicate JSON key" in import_bytes(b'{"entries":[],"entries":[]}')["error"]
    assert "UTF-8 JSON" in import_bytes(b"\x1f\x8b")["error"]
    monkeypatch.setattr(module, "MAX_DETAILS", 4)
    assert "detail records" in run(log_entry())["error"]
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "at most" in run([log_entry(), log_entry()])["error"]
    monkeypatch.setattr(module, "MAX_JSON", 8)
    assert "Decoded audit log" in import_bytes(gzip.compress(json.dumps(log_entry()).encode()))["error"]
