import base64
import gzip
import hashlib
import json
from copy import deepcopy

import pytest

from misp_modules.modules.import_mod import kubernetes_audit_import as importer

AUDIT_ID = "c594708b-e93a-4af8-9334-9dfa30b062a8"
RESOURCE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/Work/providers/Microsoft.ContainerService/managedClusters/cluster-a"


def event(stage="RequestReceived", timestamp="2026-05-22T09:30:00.123456789Z", **fields):
    return {
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Event",
        "auditID": AUDIT_ID,
        "stage": stage,
        "level": "RequestResponse",
        "stageTimestamp": timestamp,
        "requestReceivedTimestamp": "2026-05-22T09:30:00.123456789Z",
        "verb": "watch",
        "user": {
            "username": "system:serviceaccount:monitoring:monitor",
            "uid": "sa-id",
            "groups": ["system:authenticated"],
        },
        "requestURI": "/api/v1/namespaces/apps/pods?watch=true",
        "objectRef": {"namespace": "apps", "resource": "pods", "apiVersion": "v1"},
        **fields,
    }


def submitted(document, **params):
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
    query = {"data": base64.b64encode(raw).decode(), **params}
    return importer.handler(json.dumps(query))


def json_lines(events):
    return "\n".join(map(json.dumps, events)).encode()


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def links(obj, relationship):
    return [ref for ref in obj["ObjectReference"] if ref["relationship_type"] == relationship]


def test_native_json_lines_groups_all_stages_in_timestamp_order():
    received = event(sourceIPs=["203.0.113.3", "2001:0db8::3", "redacted"])
    started = event("ResponseStarted", "2026-05-22T09:30:00.123456790Z", responseStatus={"code": 200})
    completed = event(
        "ResponseComplete",
        "2026-05-22T11:30:02.000001001+02:00",
        responseStatus={"status": "Failure", "code": 403, "reason": "Forbidden", "message": "Access denied.\nDetails."},
        impersonatedUser={"username": "reviewer", "uid": "uid-test", "groups": ["read-only"]},
        annotations={"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": "policy"},
        requestObject={"secret": "raw-attachment-only"},
        userAgent="kubectl/v1.32",
    )
    result = submitted(json_lines([completed, started, received]), config={"cluster_id": "investigation-cluster"})
    assert result["summary"]["requests"] == 1
    assert result["summary"]["stages"] == 3
    assert result["summary"]["formats"] == {"native": 3}
    source, request, *stages = result["results"]["Object"]
    assert request["name"] == importer.REQUEST
    assert values(request, "audit-id") == [AUDIT_ID]
    assert values(request, "cluster-id") == ["investigation-cluster"]
    assert values(request, "verb") == ["watch"]
    assert values(request, "service-account") == ["monitoring/monitor"]
    assert values(request, "namespace") == ["apps"]
    assert values(request, "last-stage-time") == ["2026-05-22T09:30:02.000001+00:00"]
    assert request["first_seen"] != request["last_seen"]
    assert [values(stage, "stage")[0] for stage in stages] == ["RequestReceived", "ResponseStarted", "ResponseComplete"]
    assert [ref["referenced_uuid"] for ref in links(request, "contains")] == [stage["uuid"] for stage in stages]
    for stage, line in zip(stages, [3, 2, 1], strict=True):
        (ref,) = links(stage, "extracted-from")
        assert ref["referenced_uuid"] == source["uuid"]
        assert ref["comment"] == f"JSON Lines line {line}"
        assert values(stage, "audit-id") == [AUDIT_ID]
        assert not any(attr["to_ids"] for attr in stage["Attribute"])

    first, _, last = stages
    assert values(first, "source-address") == ["203.0.113.3", "2001:0db8::3", "redacted"]
    assert values(first, "ip-src") == ["203.0.113.3", "2001:db8::3"]
    assert values(last, "response-code") == ["403"]
    assert values(last, "response-message") == ["Access denied.\nDetails."]
    assert values(last, "response-reason") == ["Forbidden"]
    assert values(last, "authorization-decision") == ["forbid"]
    assert values(last, "impersonated-username") == ["reviewer"]
    assert values(last, "impersonated-user-group") == ["read-only"]
    assert values(last, "stage-time-raw") == ["2026-05-22T11:30:02.000001001+02:00"]
    assert values(last, "user-agent") == ["kubectl/v1.32"]
    assert "raw-attachment-only" not in json.dumps(result)


def test_same_stage_from_two_observations_is_preserved():
    first = event("Panic", responseStatus={"code": 500})
    second = event("Panic", responseStatus={"code": 503})
    result = submitted([first, second, deepcopy(first)])
    assert result["summary"]["stages"] == 2
    assert result["summary"]["duplicate_stages"] == 1
    _, parent, a, b = result["results"]["Object"]
    assert a["uuid"] != b["uuid"]
    assert len(links(parent, "contains")) == 2
    assert values(a, "response-code") == ["500"]
    assert values(b, "response-code") == ["503"]


def test_exact_gzip_provenance_and_stable_explicit_cluster():
    first = event()
    second = event("ResponseComplete", "2026-05-22T09:30:01Z")
    raw = gzip.compress(b"\xef\xbb\xbf" + json_lines([first, second]))
    fields = {"config": {"cluster_id": "cluster-a", "include_source": "yes"}}
    result = submitted(raw, filename="C:\\audit\\stage.json.gz", **fields)
    source, request, first_obj, _ = result["results"]["Object"]
    assert values(source, "filename") == ["stage.json.gz"]
    assert values(source, "sha256") == [hashlib.sha256(raw).hexdigest()]
    (attachment,) = (a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == raw
    _, same_request, same_stage = submitted(first, **fields)["results"]["Object"]
    assert (request["uuid"], first_obj["uuid"]) == (same_request["uuid"], same_stage["uuid"])
    assert submitted(first)["results"]["Object"][1]["uuid"] != request["uuid"]
    assert submitted(second)["results"]["Object"][1]["uuid"] != submitted(first)["results"]["Object"][1]["uuid"]


def test_native_event_list_inherits_kind_and_version_for_items():
    item = event()
    del item["apiVersion"], item["kind"]
    result = submitted({"apiVersion": "audit.k8s.io/v1", "kind": "EventList", "items": [item]})
    assert result["summary"]["stages"] == 1
    assert links(result["results"]["Object"][2], "extracted-from")[0]["comment"] == "JSON document.items[0]"


def test_untimed_stages_keep_kubernetes_stage_order_without_inventing_times():
    last = event("ResponseComplete", None, requestReceivedTimestamp=None)
    first = event("RequestReceived", None, requestReceivedTimestamp=None)
    result = submitted([last, first])
    _, request, received, completed = result["results"]["Object"]
    assert not values(request, "last-stage-time")
    assert [ref["referenced_uuid"] for ref in links(request, "contains")] == [received["uuid"], completed["uuid"]]
    assert values(received, "stage") == ["RequestReceived"]
    assert not values(received, "stage-time")


def test_eks_cloudwatch_filter_response_with_unrelated_stream_and_continuation():
    result = submitted(
        {
            "events": [
                {"logStreamName": "kube-apiserver-audit-0123", "message": json.dumps(event()), "eventId": "12345"},
                {"logStreamName": "authenticator-0123", "message": "not a Kubernetes audit event"},
                {
                    "logStreamName": "kube-apiserver-audit-4567",
                    "message": json.dumps(event("ResponseComplete", "2026-05-22T09:30:01Z")),
                    "eventId": "12346",
                },
            ],
            "nextToken": "private-cursor",
        },
        config={"cluster_id": "eks-work"},
    )
    assert result["summary"]["skipped_rows"] == 1
    assert result["summary"]["formats"] == {"eks-cloudwatch": 2}
    assert any("another page" in warning for warning in result["warnings"])
    assert "private-cursor" not in json.dumps(result)
    _, request, first, second = result["results"]["Object"]
    assert values(request, "cluster-id") == ["eks-work"]
    assert values(first, "provider-event-id") == ["12345"]
    assert values(second, "provider-log-stream") == ["kube-apiserver-audit-4567"]
    assert links(second, "extracted-from")[0]["comment"] == "JSON document.events[2]"


@pytest.mark.parametrize(
    "tokens",
    [
        {"nextForwardToken": "private-forward-cursor"},
        {"nextBackwardToken": "private-backward-cursor"},
        {"nextForwardToken": "private-forward-cursor", "nextBackwardToken": "private-backward-cursor"},
    ],
)
def test_eks_cloudwatch_get_log_events_warns_when_page_completeness_is_unknown(tokens):
    result = submitted({"events": [{"message": json.dumps(event())}], **tokens})
    assert result["summary"]["formats"] == {"eks-cloudwatch": 1}
    assert result["warnings"] == [
        "The CloudWatch GetLogEvents response has pagination tokens. "
        "Verify that all pages for the requested time range were collected."
    ]
    assert all(token not in json.dumps(result) for token in tokens.values())


def test_eks_cloudwatch_empty_get_log_events_page_surfaces_pagination_warning():
    result = submitted({"events": [], "nextForwardToken": "private-forward-cursor"})
    assert "contains no Kubernetes audit events" in result["error"]
    assert "Verify that all pages" in result["error"]
    assert "private-forward-cursor" not in result["error"]


def test_eks_cloudwatch_subscription_is_scoped_by_account_and_group():
    def batch(account):
        return {
            "owner": account,
            "logGroup": "/aws/eks/example/cluster",
            "logStream": "kube-apiserver-audit-a",
            "logEvents": [{"id": "row-1", "message": json.dumps(event())}],
        }

    wrapped = {
        "awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(batch("111111111111")).encode())).decode()}
    }
    result = submitted([wrapped, batch("222222222222")])
    assert result["summary"]["requests"] == 2
    assert result["summary"]["stages"] == 2
    _, a, b, first, second = result["results"]["Object"]
    assert a["uuid"] != b["uuid"]
    assert values(a, "cluster-id") == ["111111111111:/aws/eks/example/cluster"]
    assert values(b, "cluster-id") == ["222222222222:/aws/eks/example/cluster"]
    assert values(first, "provider-log-group") == ["/aws/eks/example/cluster"]
    assert values(second, "provider-account-id") == ["222222222222"]


def test_aks_diagnostics_and_resource_specific_table_share_a_request():
    diagnostic = {
        "records": [
            {"category": "kube-audit", "resourceId": RESOURCE.upper(), "properties": {"log": json.dumps(event())}},
            {
                "category": "kube-apiserver",
                "resourceId": RESOURCE.upper(),
                "properties": {"log": "API server process log"},
            },
        ]
    }
    row = {
        "AuditId": AUDIT_ID,
        "Type": "AKSAuditAdmin",
        "_ResourceId": RESOURCE,
        "Stage": "ResponseComplete",
        "StageReceivedTime": "2026-05-22T09:30:01.0000001Z",
        "RequestReceivedTime": "2026-05-22T09:30:00.123456789Z",
        "Verb": "update",
        "User": '{"username":"developer","groups":["system:authenticated"]}',
        "SourceIps": '["203.0.113.5"]',
        "ObjectRef": {"name": "settings", "namespace": "apps", "resource": "configmaps", "apiVersion": "v1"},
        "ResponseStatus": '{"code":200,"status":"Success"}',
    }
    query = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": key, "type": "string"} for key in row],
                "rows": [list(row.values())],
            }
        ],
        "error": {"code": "PartialError"},
    }
    result = submitted([diagnostic, query])
    assert result["summary"]["requests"] == 1
    assert result["summary"]["stages"] == 2
    assert result["summary"]["skipped_rows"] == 1
    assert any("Log Analytics reported" in warning for warning in result["warnings"])
    _, request, first, second = result["results"]["Object"]
    assert values(request, "cluster-id") == [RESOURCE.upper()]
    assert values(first, "provider-category") == ["kube-audit"]
    assert values(second, "provider-table") == ["AKSAuditAdmin"]
    assert values(second, "provider-resource-id") == [RESOURCE]
    assert values(second, "username") == ["developer"]
    assert values(second, "object-name") == ["settings"]
    assert values(second, "response-code") == ["200"]
    assert values(second, "stage-time-raw") == ["2026-05-22T09:30:01.0000001Z"]
    assert links(second, "extracted-from")[0]["comment"] == "JSON record 2.tables[0].rows[0]"


def test_aks_diagnostic_log_analytics_legacy_flat_rows_and_cluster_separation():
    record = {"Category": "kube-audit-admin", "_ResourceId": RESOURCE, "log_s": json.dumps(event())}
    other = dict(record, _ResourceId=RESOURCE.replace("cluster-a", "cluster-b"))
    result = submitted([record, other], config={"cluster_id": "configured-default"})
    assert result["summary"]["requests"] == 2
    _, a, b, *_ = result["results"]["Object"]
    assert values(a, "cluster-id") == [record["_ResourceId"]]
    assert values(b, "cluster-id") == [other["_ResourceId"]]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "contains no Kubernetes audit events"),
        (event(apiVersion="audit.k8s.io/v1beta1"), "Expected a native audit.k8s.io/v1 Event"),
        (event(auditID=None), "auditID must be nonempty"),
        (event(stage=None), "stage must be nonempty"),
        (event(timestamp="2026-05-22T09:30:00-00:00"), "known UTC offset"),
        (event(sourceIPs="203.0.113.4"), "sourceIPs must be an array"),
        ({"events": [{"logStreamName": "kube-apiserver-audit-1", "message": "{bad json"}]}, "events[0]"),
        ({"records": [{"category": "kube-audit", "properties": {}}]}, "records[0]"),
        ({"tables": [{"columns": [{"name": "AuditId"}], "rows": [[]]}]}, "wrong number of columns"),
        (b'{"apiVersion": "audit.k8s.io/v1", "auditID": "first", "auditID": "second"}', "Duplicate JSON key"),
    ],
)
def test_malformed_input_reports_an_error_without_partial_results(document, message):
    result = submitted(document)
    assert message in result["error"]
    assert "results" not in result


def test_import_limits(monkeypatch):
    monkeypatch.setattr(importer, "MAX_STAGES", 1)
    assert "unique stages" in submitted([event(), event("ResponseComplete")])["error"]
    monkeypatch.setattr(importer, "MAX_PAYLOAD", 100)
    assert "Decompressed export exceeds" in submitted(gzip.compress(json_lines([event()])))["error"]


def test_cloudwatch_subscription_byte_limit_applies_across_messages(monkeypatch):
    payload = json.dumps(
        {"logEvents": [{"message": json.dumps(event(requestObject={"metadata": "x" * 5500}))}]}
    ).encode()
    monkeypatch.setattr(importer, "MAX_PAYLOAD", len(payload) + 200)
    envelope = {"awslogs": {"data": base64.b64encode(gzip.compress(payload)).decode()}}
    assert submitted([envelope])["summary"]["stages"] == 1
    result = submitted([envelope, envelope])
    assert "Decompressed export exceeds" in result["error"]
    assert "results" not in result
