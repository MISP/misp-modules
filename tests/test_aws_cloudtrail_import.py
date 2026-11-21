import base64
import gzip
import hashlib
import json
from uuid import UUID

import pytest
from pymisp import MISPObject

from misp_modules.modules.import_mod import aws_cloudtrail_import as module

EVENT = "09c28368-12b2-4901-84ed-1633aec590a0"
OTHER_EVENT = "09c28368-12b2-4901-84ed-1633aec590a1"
SHARED = "09c28368-12b2-4901-84ed-1633aec590a2"
CALLER = "111122223333"
RECIPIENT = "444455556666"


def record(**changes):
    return {
        "eventVersion": "1.09",
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "eventID": EVENT,
        "eventTime": "2026-10-06T15:13:25Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": CALLER,
            "principalId": "AROATEST:analyst",
            "arn": f"arn:aws:sts::{CALLER}:assumed-role/Backup/analyst",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": f"arn:aws:iam::{CALLER}:role/Backup",
                    "userName": "Backup",
                }
            },
            "accessKeyId": "EXAMPLE-ACCESS-KEY",
        },
        "recipientAccountId": RECIPIENT,
        "sourceIPAddress": "2001:db8::1",
        "requestID": "request-id-123",
        "readOnly": False,
        "resources": [{"ARN": "arn:aws:s3:::example", "accountId": RECIPIENT, "type": "AWS::S3::Bucket"}],
        **changes,
    }


def result_for(data, **options):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return module.handler(json.dumps({"data": base64.b64encode(raw).decode("ascii"), **options}))


def objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def assert_valid_objects(response):
    returned = response["results"]["Object"]
    uuids = {obj["uuid"] for obj in returned}
    assert len(uuids) == len(returned)
    for obj in returned:
        definition = {} if obj["name"] == "file" else {"misp_objects_template_custom": module._template(obj["name"])}
        rebuilt = MISPObject(obj["name"], strict=True, standalone=False, **definition)
        rebuilt.from_dict(**obj)
        assert json.loads(rebuilt.to_json(strict=True))["uuid"] == obj["uuid"]
        for attr in obj["Attribute"]:
            assert attr["to_ids"] is False
            assert attr["disable_correlation"] is True
            assert UUID(attr["uuid"]).version == 5
        for ref in obj.get("ObjectReference", []):
            assert ref["referenced_uuid"] in uuids
            assert UUID(ref["uuid"]).version == 5


def test_maps_cross_account_api_event_and_keeps_sensitive_fields_out_of_default_results():
    row = record(
        errorCode="AccessDenied",
        errorMessage="EXAMPLE ERROR MESSAGE",
        requestParameters={"private": "EXAMPLE REQUEST PAYLOAD"},
        responseElements={"credentials": {"sessionToken": "EXAMPLE TOKEN"}},
    )
    raw = json.dumps({"Records": [row]}, indent=2).encode()
    result = result_for(raw, filename=r"C:\audit\trail.json")
    source = objects(result, "file")[0]
    event = objects(result, "aws-cloudtrail-event")[0]
    accounts = objects(result, "cloud-account")
    role = objects(result, "iam-role")[0]
    resource = objects(result, "cloud-resource")[0]
    digest = hashlib.sha256(raw).hexdigest()
    assert result["summary"] == {
        "records": 1,
        "events": 1,
        "duplicate_records": 0,
        "source_sha256": digest,
        "source_attached": False,
    }
    assert values(source) == {"filename": "trail.json", "size-in-bytes": str(len(raw)), "sha256": digest}
    fields = values(event)
    assert fields["event-id"] == EVENT
    assert fields["event-name"] == "PutBucketPolicy"
    assert fields["event-source"] == "s3.amazonaws.com"
    assert fields["event-time"] == "2026-10-06T15:13:25+00:00"
    assert fields["event-time-raw"] == row["eventTime"]
    assert event["first_seen"] == event["last_seen"] == fields["event-time"]
    assert fields["source-ip"] == "2001:db8::1"
    assert fields["principal-id"] == "AROATEST:analyst"
    assert fields["session-issuer-arn"] == f"arn:aws:iam::{CALLER}:role/Backup"
    assert fields["request-id"] == "request-id-123"
    assert fields["read-only"] in (False, "0", "false")
    assert fields["outcome"] == "failure"
    assert fields["error-code"] == "AccessDenied"
    assert fields["review-status"] == "unreviewed"
    assert {values(account)["account-id"] for account in accounts} == {CALLER, RECIPIENT}
    assert values(role)["role-id"] == f"arn:aws:iam::{CALLER}:role/Backup"
    assert values(resource)["resource-id"] == "arn:aws:s3:::example"
    assert values(resource)["account-id"] == RECIPIENT
    assert "region" not in values(resource)
    refs = {ref["referenced_uuid"]: ref for ref in event["ObjectReference"]}
    assert refs[source["uuid"]]["relationship_type"] == "extracted-from"
    assert refs[source["uuid"]]["comment"] == "CloudTrail record 1"
    assert len(refs) == 5
    assert "EXAMPLE" not in json.dumps(result)
    assert_valid_objects(result)


def test_gzip_preserves_exact_upload_and_an_event_id_is_stable_across_files():
    row = record(sourceIPAddress="AWS Internal")
    raw = gzip.compress(json.dumps({"Records": [row]}).encode(), mtime=0)
    compressed = result_for(raw, config={"include_source": "true"})
    plain = result_for(row, config={"include_source": "false"})
    assert compressed["summary"]["source_attached"] is True
    source = objects(compressed, "file")[0]
    attachment = next(item for item in source["Attribute"] if item["object_relation"] == "attachment")
    assert attachment["value"] == "cloudtrail.json.gz"
    assert base64.b64decode(attachment["data"]) == raw
    assert values(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    old = objects(compressed, "aws-cloudtrail-event")[0]
    new = objects(plain, "aws-cloudtrail-event")[0]
    assert old["uuid"] == new["uuid"]
    assert [attr["uuid"] for attr in old["Attribute"]] == [attr["uuid"] for attr in new["Attribute"]]
    assert old["ObjectReference"][0]["referenced_uuid"] != new["ObjectReference"][0]["referenced_uuid"]
    assert values(new)["source-address"] == "AWS Internal"
    assert "source-ip" not in values(new)
    assert values(new)["outcome"] == "unknown"
    assert_valid_objects(compressed)


def test_explicit_login_results_and_time_normalization():
    first = record(
        eventTime="2026-10-06T17:13:25.123456+02:00",
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        responseElements={"ConsoleLogin": "Success"},
    )
    second = record(eventID=OTHER_EVENT, eventName="ConsoleLogin", responseElements={"ConsoleLogin": "Failure"})
    events = objects(result_for({"Records": [first, second]}), "aws-cloudtrail-event")
    assert values(events[0])["outcome"] == "success"
    assert values(events[0])["event-time"] == "2026-10-06T15:13:25.123456+00:00"
    assert events[0]["first_seen"] == values(events[0])["event-time"]
    assert values(events[1])["outcome"] == "failure"


def test_duplicate_records_and_shared_event_id():
    first = record(sharedEventID=SHARED)
    second = record(eventID=OTHER_EVENT, sharedEventID=SHARED)
    response = result_for({"Records": [first, first, second]})
    events = objects(response, "aws-cloudtrail-event")
    assert [values(obj)["event-id"] for obj in events] == [EVENT, OTHER_EVENT]
    assert all(values(obj)["shared-event-id"] == SHARED for obj in events)
    assert response["summary"]["duplicate_records"] == 1
    assert events[1]["ObjectReference"][0]["comment"] == "CloudTrail record 3"
    assert len(objects(response, "cloud-resource")) == 1
    assert "Conflicting records" in result_for({"Records": [first, {**first, "awsRegion": "us-west-2"}]})["error"]


def test_accepts_other_native_categories_and_absent_identity():
    row = record(eventCategory="NetworkActivity", userIdentity=None, resources=None)
    values_ = values(objects(result_for(row), "aws-cloudtrail-event")[0])
    assert values_["event-category"] == "NetworkActivity"
    assert "principal-id" not in values_


@pytest.mark.parametrize("kind", ["IdentityCenterUser", "BuilderIdUser", "AssumedRole"])
def test_preserves_on_behalf_of_identity_separately_from_principal(kind):
    identity = record()["userIdentity"] if kind == "AssumedRole" else {"type": kind}
    if kind == "IdentityCenterUser":
        identity["accountId"] = CALLER
    store = f"arn:aws:identitystore::{CALLER}:identitystore/d-1234567890"
    if kind == "BuilderIdUser":
        store = "arn:aws:identitystore::aws:identitystore/builderid"
    user_id = "4fd5d19b-4854-4956-947a-c209cc5d81cd"
    identity["onBehalfOf"] = {"userId": user_id, "identityStoreArn": store}
    result = result_for(record(userIdentity=identity, resources=[]))
    (event,) = objects(result, "aws-cloudtrail-event")
    fields = values(event)
    assert fields["principal-type"] == kind
    assert fields["on-behalf-of-user-id"] == user_id
    assert fields["on-behalf-of-identity-store-arn"] == store
    if kind == "AssumedRole":
        assert fields["principal-id"] == identity["principalId"]
        assert fields["session-issuer-arn"] == identity["sessionContext"]["sessionIssuer"]["arn"]
        assert len(objects(result, "iam-role")) == 1
    else:
        assert "principal-id" not in fields
    if kind == "BuilderIdUser":
        assert "principal-account-id" not in fields
        assert {values(account)["account-id"] for account in objects(result, "cloud-account")} == {RECIPIENT}
    assert_valid_objects(result)


def test_links_non_arn_resource_ids_and_uses_only_reported_resource_scope():
    gov_arn = f"arn:aws-us-gov:ec2:us-gov-west-1:{CALLER}:instance/i-test"
    result = result_for(
        record(
            resources=[
                {"ARN": "d-1234567890", "type": "AWS::IdentityStore::IdentityStore"},
                {"ARN": "d-0987654321", "accountId": RECIPIENT},
                {"ARN": gov_arn},
            ]
        )
    )
    (event,) = objects(result, "aws-cloudtrail-event")
    entries = objects(result, "cloud-resource")
    by_identifier = {values(obj)["resource-id"]: values(obj) for obj in entries}
    assert by_identifier["d-1234567890"] == {
        "resource-id": "d-1234567890",
        "provider": "AWS",
        "type": "AWS::IdentityStore::IdentityStore",
    }
    assert by_identifier["d-0987654321"] == {
        "resource-id": "d-0987654321",
        "provider": "AWS",
        "account-id": RECIPIENT,
    }
    assert by_identifier[gov_arn]["partition"] == "aws-us-gov"
    assert by_identifier[gov_arn]["region"] == "us-gov-west-1"
    assert by_identifier[gov_arn]["account-id"] == CALLER
    linked = {ref["referenced_uuid"] for ref in event["ObjectReference"] if ref["relationship_type"] == "related-to"}
    assert all(entry["uuid"] in linked for entry in entries)
    assert_valid_objects(result)


def test_reuses_account_when_actor_and_recipient_roles_change_and_skips_missing_resource_ids():
    one = record(resources=[{"type": "AWS::S3::Bucket"}, {"ARN": ""}])
    two = record(eventID=OTHER_EVENT, recipientAccountId=CALLER, userIdentity=None, resources=[])
    response = result_for({"Records": [one, two]})
    accounts = objects(response, "cloud-account")
    assert len(accounts) == 2
    caller = next(account for account in accounts if values(account)["account-id"] == CALLER)
    events = objects(response, "aws-cloudtrail-event")
    assert all(caller["uuid"] in {ref["referenced_uuid"] for ref in event["ObjectReference"]} for event in events)
    assert not objects(response, "cloud-resource")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xff",
        b"{bad json}",
        b'{"Records":[],"Records":[]}',
        b'{"Records":NaN}',
        [],
        {"Records": []},
        {"Records": [None]},
        {"Events": [{"CloudTrailEvent": "{}"}]},
        record(eventID="invalid"),
        record(eventTime="2026-10-06T15:13:25"),
        record(eventTime="2026-10-06T15:13:25-00:00"),
        record(eventTime="2026-10-06T15:13:25+01:60"),
        record(readOnly="false"),
        record(resources=[42]),
        record(userIdentity=[]),
        record(userIdentity={"onBehalfOf": []}),
        b"\x1f\x8btruncated",
    ],
)
def test_invalid_input_returns_only_an_error(data):
    assert set(result_for(data)) == {"error"}


def test_limits(monkeypatch):
    raw = gzip.compress(json.dumps({"Records": [record()]}).encode())
    monkeypatch.setattr(module, "MAX_JSON", 64)
    assert "exceeds" in result_for(raw)["error"]
    monkeypatch.setattr(module, "MAX_UPLOAD", 1)
    assert "10 MiB" in result_for(raw)["error"]


def test_item_limits(monkeypatch):
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    assert "Records" in result_for({"Records": [record(), record(eventID=OTHER_EVENT)]})["error"]
    monkeypatch.setattr(module, "MAX_RESOURCES", 0)
    assert "resource entries" in result_for(record())["error"]


def test_metadata_and_invalid_query_or_option():
    assert module.handler() is False
    assert module.introspection()["inputSource"] == ["file"]
    assert module.introspection()["userConfig"]["include_source"]["type"] == "Boolean"
    assert module.version()["module-type"] == ["import"]
    assert set(module.handler("null")) == {"error"}
    assert set(module.handler('{"data":"!!!"}')) == {"error"}
    assert "include_source" in result_for(record(), config={"include_source": "surprise"})["error"]
