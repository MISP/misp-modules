import base64
import csv
import hashlib
import io
import json
from uuid import UUID

import pytest
from pymisp import MISPObject

from misp_modules.modules.import_mod import microsoft_audit_import as module

TENANT = "96e06478-13d2-4b97-9d4c-766afe5b2310"
OTHER_TENANT = "96e06478-13d2-4b97-9d4c-766afe5b2311"
RECORD = "96e06478-13d2-4b97-9d4c-766afe5b2312"


def sign_in(**updates):
    return {
        "id": RECORD,
        "createdDateTime": "2026-11-01T10:00:00Z",
        "userId": "user-identifier",
        "userPrincipalName": "analyst@example.test",
        "tenantId": TENANT,
        "homeTenantId": OTHER_TENANT,
        "resourceTenantId": TENANT,
        "resourceId": "resource-identifier",
        "appId": "application-identifier",
        "appDisplayName": "Example application",
        "correlationId": "request-correlation",
        "sessionId": "sign-in-session",
        "ipAddress": "2001:0db8::8",
        "status": {"errorCode": 0, "additionalDetails": "PRIVATE MFA DETAIL"},
        "conditionalAccessStatus": "notApplied",
        "isInteractive": False,
        **updates,
    }


def directory_audit(**updates):
    return {
        "id": "Directory_event_with_non_UUID_identifier",
        "activityDateTime": "2026-11-01T12:00:00.7215374+02:00",
        "activityDisplayName": "Add member to group",
        "category": "GroupManagement",
        "result": "timeout",
        "resultReason": "PRIVATE RESULT DETAIL",
        "loggedByService": "Core Directory",
        "initiatedBy": {
            "user": None,
            "app": {"appId": "application-registration", "servicePrincipalId": "tenant-service-principal-id"},
        },
        "targetResources": [
            {"id": "group-id", "type": "Group", "displayName": "Group, audit"},
            {
                "id": "user-id",
                "type": "User",
                "userPrincipalName": "member@example.test",
                "modifiedProperties": [{"newValue": "PRIVATE MODIFIED VALUE"}],
            },
        ],
        **updates,
    }


def purview(**updates):
    return {
        "Id": RECORD,
        "CreationTime": "2026-11-01T10:00:00",
        "Operation": "FileAccessed",
        "OrganizationId": TENANT,
        "Workload": "SharePoint",
        "UserId": "analyst@example.test",
        "ClientIP": "[2001:db8::23]:443",
        "RecordType": 6,
        "ResultStatus": "Succeeded",
        "ObjectId": "https://example.test/files/report",
        "SessionId": "workload-session",
        "Parameters": [{"Value": "PRIVATE AUDIT DATA"}],
        **updates,
    }


def result_for(content, **options):
    raw = content if isinstance(content, bytes) else json.dumps(content).encode()
    return module.handler(json.dumps({"data": base64.b64encode(raw).decode("ascii"), **options}))


def objects(result, name="microsoft-audit-event"):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def csv_export(*records, encoding="utf-8-sig"):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["CreationDate", "UserIds", "Operations", "AuditData"])
    for record in records:
        writer.writerow(
            ["11/01/2026 1:15 PM", "analyst@example.test", record["Operation"], json.dumps(record, indent=2)]
        )
    return stream.getvalue().encode(encoding)


def assert_valid(result):
    uuids = {obj["uuid"] for obj in result["results"]["Object"]}
    for obj in result["results"]["Object"]:
        templates = {} if obj["name"] == "file" else {"misp_objects_template_custom": module._template(obj["name"])}
        rebuilt = MISPObject(obj["name"], strict=True, standalone=False, **templates)
        rebuilt.from_dict(**obj)
        assert json.loads(rebuilt.to_json(strict=True))["uuid"] == obj["uuid"]
        for attr in obj["Attribute"]:
            assert attr["to_ids"] is False and attr["disable_correlation"] is True
            assert UUID(attr["uuid"]).version == 5
        for ref in obj.get("ObjectReference", []):
            assert ref["referenced_uuid"] in uuids and UUID(ref["uuid"]).version == 5


def test_entra_graph_page_maps_time_actor_and_tenants_with_source_metadata():
    record = sign_in(TimeGenerated="2026-11-01T10:00:37.1234567Z", IngestionTime="2026-11-01T10:04:09.8765432Z")
    raw = json.dumps({"value": [record], "@odata.nextLink": "https://example.test/PRIVATE"}).encode()
    result = result_for(raw, filename=r"C:\audit\sign-ins.json")
    (event,) = objects(result)
    (source,) = objects(result, "file")
    (tenant,) = objects(result, "cloud-account")
    fields = values(event)
    assert fields["log-type"] == "entra-sign-in"
    assert fields["record-id"] == RECORD
    assert fields["operation"] == "Sign-in"
    assert fields["event-time"] == event["first_seen"] == event["last_seen"] == "2026-11-01T10:00:00+00:00"
    assert fields["time-generated"] == "2026-11-01T10:00:37.123456+00:00"
    assert fields["time-generated-raw"] == record["TimeGenerated"]
    assert fields["ingestion-time"] == "2026-11-01T10:04:09.876543+00:00"
    assert fields["ingestion-time-raw"] == record["IngestionTime"]
    assert fields["tenant-id"] == fields["resource-tenant-id"] == TENANT
    assert fields["home-tenant-id"] == OTHER_TENANT
    assert fields["actor-id"] == record["userId"]
    assert fields["actor-upn"] == record["userPrincipalName"]
    assert fields["session-id"] == record["sessionId"]
    assert fields["correlation-id"] == record["correlationId"]
    assert fields["source-ip"] == "2001:db8::8"
    assert fields["source-address"] == record["ipAddress"]
    assert fields["outcome"] == "success" and fields["result-code"] == "0"
    assert fields["interactive"] in (False, "0", "false")
    assert fields["review-status"] == "unreviewed"
    assert values(tenant) == {"provider": "Microsoft", "account-id": TENANT}
    assert values(source)["filename"] == "sign-ins.json"
    assert values(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    references = {ref["referenced_uuid"]: ref for ref in event["ObjectReference"]}
    assert references[source["uuid"]]["relationship_type"] == "extracted-from"
    assert references[source["uuid"]]["comment"] == "Audit record 1"
    assert references[tenant["uuid"]]["comment"] == "Reporting Microsoft tenant"
    assert result["warnings"]
    assert "PRIVATE" not in json.dumps(result)
    assert_valid(result)


def test_time_generated_alone_does_not_supply_ingestion_time():
    (event,) = objects(result_for(sign_in(TimeGenerated="2026-11-01T10:00:37Z")))
    fields = values(event)
    assert fields["time-generated"] == "2026-11-01T10:00:37+00:00"
    assert "ingestion-time" not in fields and "ingestion-time-raw" not in fields


def test_entra_directory_audit_keeps_target_groups_and_original_precision():
    record = directory_audit()
    result = result_for([record], config={"tenant_id": TENANT.upper()})
    (event,) = objects(result)
    fields = values(event)
    assert fields["record-id"] == record["id"]
    assert fields["event-time"] == "2026-11-01T10:00:00.721537+00:00"
    assert fields["event-time-raw"] == record["activityDateTime"]
    assert fields["actor-id"] == fields["service-principal-id"] == "tenant-service-principal-id"
    assert fields["application-id"] == "application-registration"
    assert fields["outcome"] == "timeout"
    targets = [attr for attr in event["Attribute"] if attr["object_relation"] == "target-resource"]
    assert [json.loads(attr["value"]) for attr in targets] == [
        {"id": "group-id", "type": "Group", "displayName": "Group, audit"},
        {"id": "user-id", "type": "User", "userPrincipalName": "member@example.test"},
    ]
    assert len({attr["uuid"] for attr in targets}) == 2
    assert "PRIVATE" not in json.dumps(result)
    assert_valid(result)


def test_entra_service_principal_and_sign_in_error_are_mapped_without_invented_user():
    (event,) = objects(
        result_for(
            {
                "id": RECORD,
                "createdDateTime": "2026-11-01T10:00:00Z",
                "servicePrincipalId": "service-principal",
                "status": {"errorCode": 53003},
            }
        )
    )
    fields = values(event)
    assert fields["actor-id"] == fields["service-principal-id"] == "service-principal"
    assert fields["outcome"] == "failure"
    assert fields["result-code"] == "53003"
    assert "actor-upn" not in fields
    assert "tenant-id" not in fields


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_purview_csv_digest_opt_in_preserves_upload_and_matches_json_identity(encoding):
    record = purview()
    raw = csv_export(record, encoding=encoding)
    csv_result = result_for(raw, config={"include_source": "true"})
    json_result = result_for(record)
    (event,) = objects(csv_result)
    fields = values(event)
    assert fields["event-time"] == "2026-11-01T10:00:00+00:00"
    assert fields["event-time-raw"] == record["CreationTime"]
    assert fields["operation"] == record["Operation"]
    assert fields["outcome"] == "success"
    assert fields["source-ip"] == "2001:db8::23"
    assert fields["record-type"] == "6"
    assert fields["resource-id"] == record["ObjectId"]
    assert fields["session-id"] == record["SessionId"]
    assert event["uuid"] == objects(json_result)[0]["uuid"]
    (source,) = objects(csv_result, "file")
    assert values(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    attachment = next(attr for attr in source["Attribute"] if attr["object_relation"] == "attachment")
    assert attachment["value"] == "microsoft-audit.csv"
    assert base64.b64decode(attachment["data"]) == raw
    assert csv_result["summary"]["source_attached"] is True
    assert "PRIVATE" not in json.dumps(json_result)
    assert_valid(csv_result)


@pytest.mark.parametrize("kind", [15, "AzureActiveDirectoryStsLogon"])
def test_purview_sts_http_success_does_not_claim_a_successful_sign_in(kind):
    record = purview(RecordType=kind, Operation="UserLoggedIn", ResultStatus="Succeeded")
    fields = values(objects(result_for(record))[0])
    assert fields["result-status"] == "Succeeded"
    assert fields["outcome"] == "unknown"
    fields = values(objects(result_for({**record, "LogonError": "PRIVATE login error"}))[0])
    assert fields["outcome"] == "failure"


def test_deduplication_is_scoped_to_tenant_and_source_type():
    sign_in_ = sign_in()
    purview_ = purview()
    another_tenant = sign_in(tenantId=OTHER_TENANT)
    response = result_for([sign_in_, sign_in_, purview_, another_tenant])
    events = objects(response)
    assert response["summary"]["duplicate_records"] == 1
    assert len({event["uuid"] for event in events}) == 3
    assert len(objects(response, "cloud-account")) == 2
    assert events[1]["ObjectReference"][0]["comment"] == "Audit record 3"
    conflict = result_for([sign_in_, {**sign_in_, "ipAddress": "192.0.2.15"}])
    assert set(conflict) == {"error"} and "Conflicting records" in conflict["error"]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xff",
        b"{invalid json}",
        b'{"value":[],"value":[]}',
        b'{"value":[NaN]}',
        b"CreationDate,AuditData,AuditData\n",
        b"CreationDate,AuditData\ninvalid\n",
        b'AuditData\n"{malformed}"\n',
        [],
        {"value": None},
        {"records": [sign_in()]},
        [sign_in(), None],
        sign_in(createdDateTime="2026-11-01T10:00:00"),
        sign_in(createdDateTime="2026-11-01T10:00:00-00:00"),
        sign_in(createdDateTime="2026-11-01T10:00:00+00:60"),
        sign_in(status={"errorCode": True}),
        sign_in(isInteractive="false"),
        sign_in(auditData="unsupported Graph security record shape"),
        directory_audit(targetResources=[False]),
        purview(OrganizationId="not-a-tenant-id"),
    ],
)
def test_invalid_input_returns_only_error(data):
    assert set(result_for(data)) == {"error"}


def test_limits_and_options(monkeypatch):
    assert module.handler() is False
    assert set(module.handler('{"data":"!!!"}')) == {"error"}
    assert set(result_for(sign_in(), config={"tenant_id": OTHER_TENANT})) == {"error"}
    assert "include_source" in result_for(sign_in(), config={"include_source": "maybe"})["error"]
    assert module.version()["module-type"] == ["import"]
    assert module.introspection()["userConfig"]["include_source"]["type"] == "Boolean"
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "1,000 audit records" in result_for([sign_in(), directory_audit()])["error"]
    monkeypatch.setattr(module, "MAX_TARGETS", 1)
    assert "targetResources" in result_for(directory_audit())["error"]
    monkeypatch.setattr(module, "MAX_UPLOAD", 1)
    assert "10 MiB" in result_for(sign_in())["error"]
