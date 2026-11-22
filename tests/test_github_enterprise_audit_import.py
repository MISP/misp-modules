import base64
import csv
import gzip
import hashlib
import json
from io import StringIO

import pytest

from misp_modules.modules.import_mod import github_enterprise_audit_import as importer


def audit_event(**fields):
    return {
        "action": "org.add_member",
        "_document_id": "event-TQ8m19",
        "actor": "admin-user",
        "actor_id": 612345678901234567,
        "created_at": 1606929874512,
        "@timestamp": 1606929874812,
        "business": "sample-enterprise",
        "business_id": "9007199254740993",
        "org": "sample-org",
        "org_id": 79,
        "user": "added-user",
        "user_id": 101,
        "permission": "member",
        **fields,
    }


def git_records():
    return [
        {
            "action": "git.clone",
            "@timestamp": 1606929874512,
            "_document_id": "clone-id",
            "actor": "ci-app[bot]",
            "actor_is_bot": True,
            "actor_ip": "2001:0db8::8",
            "user_agent": "git/2.49.0",
            "business": "sample-enterprise",
            "org": "sample-org",
            "repository": "sample-org/internal-repo",
            "repository_id": 823,
            "transport_protocol_name": "ssh",
            "external_id": "git-request-1",
        },
        {
            "action": "git.push",
            "@timestamp": 1606929874812,
            "_document_id": "push-id",
            "actor": "admin-user",
            "repo": "sample-org/internal-repo",
            "org": "sample-org",
            "repo_id": 823,
            "transport_protocol": 2,
        },
    ]


def submit(document, **fields):
    raw = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
    return importer.handler(json.dumps({"data": base64.b64encode(raw).decode("ascii"), **fields}))


def attr(obj, relation):
    return [entry for entry in obj["Attribute"] if entry["object_relation"] == relation]


def values(obj, relation):
    return [entry["value"] for entry in attr(obj, relation)]


def test_audit_json_preserves_membership_policy_app_and_scope():
    member = audit_event(actor_is_bot=False, user_agent="ExampleBrowser/1.0")
    policy = audit_event(
        _document_id="policy",
        action="business.update_default_repository_permission",
        org=None,
        org_id=None,
        user=None,
        user_id=None,
        permission=None,
        data={"old_permission": "write", "permission": "read", "config": {"enabled": False, "number": 0}},
    )
    app = audit_event(
        _document_id="app",
        action="integration_installation.create",
        repo="sample-org/internal-repo",
        repo_id=823,
        actor_location={"country_code": "LU"},
        name="Example Integration",
        integration="example-integration",
        application_client_id="Iv1.ad45",
        oauth_application_id=162,
        repository_selection="selected",
        programmatic_access_type="GitHub App installation token",
    )
    result = submit([member, policy, app])
    source, first, second, third = result["results"]["Object"]
    assert result["summary"]["event_kinds"] == {"audit": 3}
    for i, (obj, record) in enumerate(zip((first, second, third), (member, policy, app), strict=True), 1):
        assert obj["name"] == "github-audit-event"
        assert values(obj, "enterprise") == ["sample-enterprise"]
        assert values(obj, "enterprise-id") == ["9007199254740993"]
        assert values(obj, "event-time") == ["2020-12-02T17:24:34.512000+00:00"]
        assert values(obj, "created-at-raw") == ["1606929874512"]
        assert values(obj, "timestamp-raw") == ["1606929874812"]
        assert values(obj, "github-host") == ["github.com"]
        (ref,) = obj["ObjectReference"]
        assert (ref["relationship_type"], ref["referenced_uuid"], ref["comment"]) == (
            "extracted-from",
            source["uuid"],
            f"JSON record {i}",
        )
        assert json.loads(values(obj, "raw-record")[0]) == record
        assert attr(obj, "raw-record")[0]["disable_correlation"]
        assert not any(attribute["to_ids"] for attribute in obj["Attribute"])
    assert not attr(source, "attachment")
    assert values(first, "organization") == ["sample-org"]
    assert values(first, "organization-id") == ["79"]
    assert values(first, "actor-id") == ["612345678901234567"]
    assert values(first, "actor") == ["admin-user"]
    assert attr(first, "actor")[0]["type"] == "github-username"
    assert not attr(first, "actor")[0]["disable_correlation"]
    (bot,) = attr(first, "actor-is-bot")
    assert (bot["type"], bot["value"], bot["disable_correlation"]) == ("boolean", "0", True)
    (user_agent,) = attr(first, "user-agent")
    assert (user_agent["type"], user_agent["value"], user_agent["disable_correlation"]) == (
        "user-agent",
        "ExampleBrowser/1.0",
        False,
    )
    assert values(first, "target-user") == ["added-user"]
    assert values(second, "action-category") == ["business"]
    assert values(second, "old-permission") == ["write"]
    assert values(second, "permission") == ["read"]
    assert not attr(second, "organization") and not attr(second, "repository")
    assert values(third, "repository") == ["sample-org/internal-repo"]
    assert values(third, "repository-id") == ["823"]
    assert values(third, "source-country-code") == ["LU"]
    assert values(third, "application-name") == ["Example Integration"]
    assert values(third, "application-client-id") == ["Iv1.ad45"]
    assert not attr(third, "application-client-id")[0]["disable_correlation"]
    assert values(third, "oauth-application-id") == ["162"]
    assert values(third, "repository-selection") == ["selected"]


def test_export_csv_keeps_dotted_headers_strings_and_multiline_cells():
    header = [
        "action",
        "actor",
        "created_at",
        "org",
        "repo",
        "data.permission",
        "data.old_user",
        "actor_location.country_code",
        "actor_is_bot",
        "data.user_agent",
        "data.events",
        "data.message",
    ]
    row = [
        "repo.add_member",
        "admin-user",
        "2024-01-02T16:10:11.123456789+02:00",
        "sample-org",
        "sample-org/internal",
        "write",
        "previous-user",
        "LU",
        " False ",
        "ExampleClient/3.1",
        '["push","issues"]',
        'note with "quotes", a comma\nand a newline',
    ]
    content = StringIO(newline="")
    csv.writer(content).writerows([header, row])
    result = submit(content.getvalue().encode("utf-8-sig"))
    assert result["summary"]["format"] == "csv"
    _, event = result["results"]["Object"]
    assert values(event, "event-time") == ["2024-01-02T14:10:11.123456+00:00"]
    assert values(event, "permission") == ["write"]
    assert values(event, "previous-user") == ["previous-user"]
    assert values(event, "source-country-code") == ["LU"]
    assert values(event, "actor-is-bot") == ["0"]
    assert values(event, "user-agent") == ["ExampleClient/3.1"]
    assert json.loads(values(event, "raw-record")[0]) == dict(zip(header, row, strict=True))
    assert event["ObjectReference"][0]["comment"] == "CSV row ending at line 3"


def test_git_event_gzip_json_lines_source_and_transport():
    first, second = git_records()
    upload = gzip.compress((json.dumps(first) + "\n\n" + json.dumps(second) + "\n").encode())
    result = submit(upload, filename="C:\\export\\export-example.json.gz", config={"include_source": True})
    assert result["summary"] == {
        "format": "json-lines",
        "records": 2,
        "events": 2,
        "event_kinds": {"git": 2},
        "duplicate_records": 0,
        "source_sha256": hashlib.sha256(upload).hexdigest(),
        "source_attached": True,
    }
    source, clone, push = result["results"]["Object"]
    assert values(source, "filename") == ["export-example.json.gz"]
    assert values(source, "size-in-bytes") == [str(len(upload))]
    assert base64.b64decode(attr(source, "attachment")[0]["data"]) == upload
    assert values(clone, "repository") == values(push, "repository") == ["sample-org/internal-repo"]
    assert values(clone, "repository-id") == values(push, "repository-id") == ["823"]
    assert values(clone, "event-kind") == ["git"]
    assert values(clone, "git-external-id") == ["git-request-1"]
    assert values(clone, "transport") == ["ssh"]
    assert values(push, "transport") == ["2"]
    assert values(clone, "ip-src") == ["2001:db8::8"]
    assert values(clone, "actor-is-bot") == ["1"]
    assert values(clone, "user-agent") == ["git/2.49.0"]
    assert values(clone, "created-at-raw") == []
    assert values(clone, "event-time") == ["2020-12-02T17:24:34.512000+00:00"]
    assert clone["ObjectReference"][0]["comment"] == "JSON Lines line 1"
    assert push["ObjectReference"][0]["comment"] == "JSON Lines line 3"


def test_unrecognized_bot_flag_stays_in_raw_record():
    record = audit_event(actor_is_bot="unknown")
    _, event = submit(record)["results"]["Object"]
    assert not attr(event, "actor-is-bot")
    assert json.loads(values(event, "raw-record")[0])["actor_is_bot"] == "unknown"


def test_native_id_and_host_scope():
    record = audit_event(repo="sample-org/internal")
    result = submit([record, dict(record)])
    assert result["summary"]["duplicate_records"] == 1
    original = result["results"]["Object"][1]
    _, cloud = submit(record)["results"]["Object"]
    _, server = submit(record, config={"github_host": "Git.Example.org"})["results"]["Object"]
    assert original["uuid"] == cloud["uuid"] != server["uuid"]
    assert values(server, "github-host") == ["git.example.org"]
    for relation in ("actor", "target-user", "repository"):
        assert attr(server, relation)[0]["disable_correlation"]
        assert not attr(cloud, relation)[0]["disable_correlation"]
    conflicting = submit([record, audit_event(action="org.remove_member")])
    assert "JSON record 2: Conflicting records share the same _document_id" in conflicting["error"]


def test_preserves_idless_repeats_and_raw_placeholder():
    record = audit_event(_document_id="", actor="[redacted]", actor_ip="REDACTED")
    _, first, second = submit([record, record])["results"]["Object"]
    assert first["uuid"] != second["uuid"]
    assert values(first, "actor-raw") == ["[redacted]"]
    assert values(first, "source-address") == ["REDACTED"]
    assert not attr(first, "actor") and not attr(first, "ip-src")


def test_large_record_fragments_reassemble_without_losing_whitespace():
    record = audit_event(data={"message": " x  " * 10000, "pattern": '\\"\né'})
    _, event = submit(record)["results"]["Object"]
    assert not attr(event, "raw-record")
    fragments = attr(event, "raw-record-fragment")
    assert len(fragments) > 1
    evidence = "".join(json.loads(fragment["value"]) for fragment in fragments)
    assert json.loads(evidence) == record
    assert all(len(fragment["value"]) <= 32768 and fragment["disable_correlation"] for fragment in fragments)
    assert [item["comment"] for item in fragments] == [
        f"Part {i} of {len(fragments)}" for i in range(1, len(fragments) + 1)
    ]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "contains no audit events"),
        ([audit_event(created_at=True)], "created_at must be epoch milliseconds"),
        ([audit_event(created_at="2026-11-01T12:00:00-00:00")], "known UTC offset"),
        ([audit_event(action="org")], "Expected a GitHub audit action"),
        ([audit_event(), 1], "JSON record 2: Each audit record must be an object"),
        (b"created_at,other\n1234,repo.access\n", "Expected GitHub CSV"),
        (b"created_at,action,action\n1234,repo.access,repo.create\n", "Expected GitHub CSV"),
        (b"created_at,action\n1234,repo.access,unexpected\n", "line 2 has the wrong number of columns"),
        (b'{"created_at":1,"action":"git.fetch"}\n{"action":\n', "Invalid JSON Lines at line 2"),
        (b'{"created_at":1,"action":"git.fetch","action":"git.clone"}', "Duplicate JSON key"),
        (b"\x1f\x8bgarbled", "Unable to decode"),
    ],
)
def test_invalid_exports_fail_without_partial_results(document, message):
    result = submit(document)
    assert message in result["error"]
    assert "results" not in result


def test_import_limits_and_host_validation(monkeypatch):
    assert (
        "GitHub host must be a hostname" in submit(audit_event(), config={"github_host": "https://git.example/"})[
            "error"
        ]
    )
    monkeypatch.setattr(importer, "MAX_RECORDS", 1)
    assert "Export exceeds 1 audit records" in submit(git_records())["error"]
    monkeypatch.setattr(importer, "MAX_PAYLOAD", 100)
    data = gzip.compress(json.dumps(git_records()).encode())
    assert "Decompressed export exceeds" in submit(data)["error"]
