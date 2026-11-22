import base64
import copy
import gzip
import hashlib
import json

import pytest
from pymisp import MISPObject

from misp_modules.modules.import_mod import azure_activity_log_import as module

SUBSCRIPTION = "657c379e-d767-4bca-967c-a1924c1472af"
SCOPE = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-example"
ASSIGNMENT = SCOPE + "/providers/Microsoft.Authorization/roleAssignments/assignment-1"
OPERATION = "Microsoft.Authorization/roleAssignments/write"
CORRELATION = "37ed8eb7-231a-445d-8db7-eed3c1c5e67d"
EVENT_ID = "93b5996d-2807-48e4-bf19-dbe7b5825ce8"


def localizable(value, label=None):
    return {"value": value, "localizedValue": label or value}


def arm():
    return {
        "eventDataId": EVENT_ID,
        "id": f"/subscriptions/{SUBSCRIPTION}/events/{EVENT_ID}/ticks/123",
        "eventName": localizable("EndRequest", "End request"),
        "eventTimestamp": "2026-11-22T16:15:12.1234567+01:00",
        "submissionTimestamp": "2026-11-22T15:15:13.0000001Z",
        "category": localizable("Administrative"),
        "operationName": localizable(OPERATION, "Create role assignment"),
        "operationId": "operation-shared",
        "resourceId": ASSIGNMENT,
        "resourceGroupName": "rg-example",
        "resourceProviderName": localizable("Microsoft.Authorization"),
        "caller": "operator@example.test",
        "claims": {"oid": "caller-object", "appid": "client-application", "tid": "caller-directory"},
        "correlationId": CORRELATION,
        "status": localizable("Succeeded"),
        "subStatus": localizable("Created", "Created (HTTP Status Code: 201)"),
        "httpRequest": {"clientIpAddress": "2001:0db8::1", "clientRequestId": "request-1"},
        "authorization": {
            "action": OPERATION,
            "scope": ASSIGNMENT,
            "evidence": {
                "principalId": "authorizing-principal",
                "principalType": "User",
                "roleAssignmentId": "authorizing-assignment",
                "roleDefinitionId": "authorizing-role",
                "roleAssignmentScope": SCOPE,
                "role": "User Access Administrator",
            },
        },
        "properties": {
            "statusCode": 201,
            "requestbody": json.dumps(
                {"Properties": {"PrincipalId": "requested-principal", "RoleDefinitionId": "role-request"}}
            ),
            "responseBody": json.dumps(
                {
                    "properties": {
                        "principalId": "assigned-principal",
                        "principalType": "ServicePrincipal",
                        "roleDefinitionId": "assigned-role",
                        "scope": SCOPE,
                    },
                    "id": "reported-target-assignment",
                    "arbitrary": "not-projected",
                }
            ),
        },
    }


def diagnostic():
    sample = arm()
    return {
        "time": sample["eventTimestamp"],
        "resourceId": sample["resourceId"],
        "operationName": OPERATION.upper(),
        "category": "Write",
        "resultType": "Success",
        "resultSignature": "Succeeded.Created",
        "correlationId": CORRELATION,
        "callerIpAddress": "192.0.2.10",
        "identity": {
            "authorization": sample["authorization"],
            "claims": {
                module.CLAIM_URI + "upn": "actor@example.test",
                module.IDENTITY_URI + "objectidentifier": "actor-oid",
            },
        },
        "properties": {"statusCode": "Created", "eventDataId": EVENT_ID},
    }


def query_bytes(raw, **parameters):
    return module.handler(json.dumps({"data": base64.b64encode(raw).decode(), **parameters}))


def query(document, **parameters):
    return query_bytes(json.dumps(document).encode(), **parameters)


def objects(result):
    assert "error" not in result, result
    source, *events = result["results"]["Object"]
    assert source["name"] == "file"
    for obj in (source, *events):
        options = {} if obj["name"] == "file" else {"misp_objects_template_custom": module._template()}
        parsed = MISPObject(obj["name"], strict=True, standalone=False, **options)
        parsed.from_dict(**obj)
        assert json.loads(parsed.to_json(strict=True))["uuid"] == obj["uuid"]
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    for event in events:
        assert event["name"] == "azure-activity-log-event"
        (ref,) = event["ObjectReference"]
        assert ref["relationship_type"] == "extracted-from" and ref["referenced_uuid"] == source["uuid"]
    return source, events


def fields(obj):
    return {attribute["object_relation"]: attribute["value"] for attribute in obj["Attribute"]}


def test_arm_retains_role_assignment_target_and_caller_authorization():
    response = query(arm())
    source, (event,) = objects(response)
    values = fields(event)
    assert response["summary"]["schemas"] == {"arm": 1}
    assert values["event-id"] == EVENT_ID and values["event-name"] == "EndRequest"
    assert values["correlation-id"] == CORRELATION and values["operation-id"] == "operation-shared"
    assert values["operation"] == OPERATION and values["resource-id"] == ASSIGNMENT
    assert values["subscription-id"] == SUBSCRIPTION
    assert values["caller"] == "operator@example.test" and values["caller-source"] == "caller"
    assert values["caller-object-id"] == "caller-object" and values["caller-application-id"] == "client-application"
    assert values["caller-tenant-id"] == "caller-directory" and "tenant-id" not in values
    assert values["caller-address"] == "2001:0db8::1" and values["source-ip"] == "2001:db8::1"
    assert values["client-request-id"] == "request-1"
    assert values["result"] == "Succeeded" and values["result-detail"] == "Created" and values["status-code"] == "201"
    assert values["authorization-principal-id"] == "authorizing-principal"
    assert values["authorization-role-assignment-id"] == "authorizing-assignment"
    assert values["authorization-role-definition-id"] == "authorizing-role"
    assert values["assigned-principal-id"] == "assigned-principal"
    assert values["assigned-role-assignment-id"] == "reported-target-assignment"
    assert values["assigned-role-definition-id"] == "assigned-role" and values["assignment-source"] == "responseBody"
    assert values["event-time"] == "2026-11-22T15:15:12.123456+00:00"
    assert values["event-time-raw"] == "2026-11-22T16:15:12.1234567+01:00"
    assert values["submission-time-raw"] == "2026-11-22T15:15:13.0000001Z"
    assert event["first_seen"] == event["last_seen"]
    assert "attachment" not in fields(source) and "not-projected" not in json.dumps(response)


def test_diagnostic_identity_result_and_category_have_native_semantics():
    record = diagnostic()
    explicit = copy.deepcopy(record)
    explicit["properties"]["eventCategory"] = "Policy"
    explicit["resultType"] = "Failure"
    result = query({"records": [record, explicit]})
    _, events = objects(result)
    assert result["summary"]["format"] == "diagnostic-envelope"
    assert result["summary"]["events"] == 2 and result["summary"]["duplicate_records"] == 0
    first, second = map(fields, events)
    assert first["category"] == "Administrative" and first["diagnostic-category"] == "Write"
    assert second["category"] == "Policy" and second["result"] == "Failure"
    assert first["caller"] == "actor@example.test" and first["caller-source"].startswith("identity.claims.")
    assert first["caller-object-id"] == "actor-oid"
    assert first["result"] == "Success" and first["result-signature"] == "Succeeded.Created"
    assert first["source-ip"] == "192.0.2.10" and first["correlation-id"] == CORRELATION
    assert "event-id" not in first
    assert events[1]["ObjectReference"][0]["comment"] == "Azure Activity Log record 2"


def test_saved_log_analytics_table_preserves_workspace_and_application_context():
    row = {
        "Type": "AzureActivity",
        "EventDataId": EVENT_ID,
        "Caller": "",
        "Claims": json.dumps({"upn": "legacy@example.test", "tid": "legacy-tenant"}),
        "Claims_d": {"appid": "client-application", "tid": "caller-directory"},
        "Authorization": json.dumps({"action": OPERATION}),
        "TimeGenerated": "2026-11-22T15:15:12.1234567Z",
        "EventSubmissionTimestamp": "2026-11-22T15:15:13Z",
        "_ResourceId": ASSIGNMENT,
        "TenantId": "workspace-42",
        "OperationNameValue": OPERATION,
        "ActivityStatusValue": "Succeeded",
        "CorrelationId": CORRELATION,
    }
    table = {"columns": [{"name": key} for key in row], "rows": [list(row.values())]}
    response = query({"tables": [table]})
    _, (event,) = objects(response)
    values = fields(event)
    assert response["summary"]["format"] == "log-analytics-response"
    assert values["workspace-id"] == "workspace-42" and values["caller-tenant-id"] == "caller-directory"
    assert "caller" not in values and "tenant-id" not in values
    assert values["caller-application-id"] == "client-application" and values["authorization-action"] == OPERATION
    assert values["resource-id"] == ASSIGNMENT and values["source-schema"] == "log-analytics"
    assert fields(objects(query(row))[1][0]) == values
    row["Claims_d"] = {}
    fallback = fields(objects(query(row))[1][0])
    assert fallback["caller"] == "legacy@example.test" and fallback["caller-source"] == "Claims.upn"


def test_gzip_rest_page_keeps_source_and_stages_with_shared_correlation():
    final = arm()
    first = dict(final, eventDataId="start-id", eventName=localizable("BeginRequest"), status=localizable("Started"))
    first["id"] = "/subscriptions/sub/events/start-id/ticks/001"
    data = gzip.compress(("\ufeff" + json.dumps({"value": [first, final, final], "nextLink": "private-link"})).encode())
    result = query_bytes(data, filename=r"C:\logs\audit.json.gz", config={"include_source": "true"})
    source, events = objects(result)
    assert result["summary"]["format"] == "rest-response"
    assert result["summary"]["has_next_page"] and result["summary"]["duplicate_records"] == 1
    assert len(events) == 2 and events[0]["uuid"] != events[1]["uuid"]
    assert fields(events[0])["correlation-id"] == fields(events[1])["correlation-id"] == CORRELATION
    assert fields(events[0])["result"] == "Started"
    assert fields(source)["sha256"] == hashlib.sha256(data).hexdigest()
    assert fields(source)["filename"] == "audit.json.gz"
    (attachment,) = (attr for attr in source["Attribute"] if attr["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == data
    assert "private-link" not in json.dumps(result)
    assert objects(query([final]))[1][0]["uuid"] == events[1]["uuid"]


def test_partial_export_uses_reported_entity_and_keeps_missing_event_time():
    record = arm()
    del record["eventTimestamp"]
    del record["resourceId"]
    record["properties"]["entity"] = ASSIGNMENT
    record["properties"]["responseBody"] = "<omitted>"
    result = query(record)
    _, (event,) = objects(result)
    values = fields(event)
    assert values["resource-id"] == ASSIGNMENT and values["assigned-principal-id"] == "requested-principal"
    assert values["assignment-source"] == "requestbody"
    assert "event-time" not in values and "first_seen" not in event
    assert "omitted" not in json.dumps(result)


def test_cli_projection_with_authorization_action_and_selected_properties():
    entry = arm()
    projected = {field: entry[field] for field in ("authorization", "eventTimestamp", "caller", "properties")}
    projected["properties"]["entity"] = ASSIGNMENT
    _, (event,) = objects(query([projected]))
    values = fields(event)
    assert values["operation"] == OPERATION and values["operation-source"] == "authorization.action"
    assert values["resource-id"] == ASSIGNMENT
    assert values["assigned-principal-id"] == "assigned-principal"
    assert values["status-code"] == "201" and "result" not in values


def test_conflicting_identifiers_fail_with_record_context():
    original = arm()
    changed = dict(original, status=localizable("Failed"))
    response = query([original, changed])
    assert set(response) == {"error"}
    assert "Record 2" in response["error"] and "Conflicting records" in response["error"]


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"value":[],"nextLink":"placeholder"}', "another page"),
        (b'{"value":[]}', "no Azure Activity Log events"),
        (b'{"records":[{"time":"2026-11-22T00:00:00Z","category":"SignInLogs","operationName":"Sign-in"}]}', "schema"),
        (
            b'{"records":[{"time":"2026-11-22T00:00:00Z","category":"AuditEvent","operationName":"SecretGet"}]}',
            "schema",
        ),
        (b'{"value":[],"value":[]}', "Duplicate JSON key"),
        (
            b'{"tables":[{"columns":[{"name":"Type"}],"rows":[["AzureActivity","extra"]]}]}',
            "match its declared columns",
        ),
        (
            b'{"eventTimestamp":"2026-11-22T00:00:00","operationName":"Microsoft.Storage/storageAccounts/write"}',
            "offset-aware",
        ),
        (b"\x1f\x8b", "UTF-8 JSON"),
    ],
)
def test_malformed_or_unrelated_uploads_fail(raw, message):
    response = query_bytes(raw)
    assert set(response) == {"error"}
    assert message in response["error"]


def test_bounded_export_and_envelope_schema(monkeypatch):
    assert "envelope expects" in query({"value": [diagnostic()]})["error"]
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "at most 1,000" in query([arm(), arm()])["error"]
    monkeypatch.setattr(module, "MAX_JSON", 3)
    assert "Decoded Activity Log" in query_bytes(gzip.compress(b'{"value":[]}'))["error"]
