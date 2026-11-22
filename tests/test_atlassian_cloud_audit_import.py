import base64
import csv
import gzip
import hashlib
import json
from io import StringIO

import pytest

from misp_modules.modules.import_mod import atlassian_cloud_audit_import as importer


def record(event_id="event-42", **attrs):
    return {
        "id": event_id,
        "type": "events",
        "attributes": {
            "time": "2025-02-27T18:50:12.281Z",
            "action": "user_access_granted",
            "actor": {
                "id": "account-17",
                "name": "Example Admin",
                "email": "admin@example.org",
                "auth": {"authType": "api-token", "tokenId": "token-id", "tokenLabel": "Audit integration"},
                "onBehalfOf": {"id": "account-9", "email": "delegate@example.org"},
                "app": {"id": "app-4", "type": "forge", "attributes": {"displayName": "Workflow"}},
            },
            "context": [
                {
                    "id": "account-21",
                    "type": "user",
                    "attributes": {
                        "displayName": "Member",
                        "email": "member@example.org",
                        "access": {"was": False, "now": True},
                    },
                },
                {"id": "group-6", "type": "group", "attributes": {"name": "site-admins"}},
            ],
            "container": [
                {"id": "site-2", "type": "site", "attributes": {"name": "example.atlassian.net"}},
                {"id": "org-1", "type": "organization", "attributes": {"name": "Example Org"}},
            ],
            "location": {"ip": "2001:0db8::3", "countryName": "France", "city": "Paris"},
            **attrs,
        },
        "links": {"self": "https://api.atlassian.com/admin/v1/orgs/org-1/events/" + event_id},
        "message": {"content": "opaque-ciphertext", "format": "example-format"},
    }


def submitted(document, **params):
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
    query = {"data": base64.b64encode(raw).decode("ascii"), **params}
    return importer.handler(json.dumps(query))


def csv_file(header, row):
    output = StringIO(newline="")
    csv.writer(output).writerows([header, row])
    return output.getvalue().encode("utf-8-sig")


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def attrs(obj, relation):
    return [a for a in obj["Attribute"] if a["object_relation"] == relation]


def links(obj, relationship):
    return [ref for ref in obj["ObjectReference"] if ref["relationship_type"] == relationship]


def test_api_page_preserves_scope_authentication_and_ordered_entities():
    event = record()
    result = submitted(
        {
            "data": [event],
            "meta": {"next": "opaque-pagination-cursor", "page_size": 1},
            "links": {
                "self": "/admin/v1/orgs/org-1/events",
                "next": "/admin/v1/orgs/org-1/events?cursor=another-cursor",
            },
        },
        config={"organization_id": "fallback-org", "site": "fallback-site"},
    )
    assert result["summary"]["format"] == "json"
    assert result["summary"]["entities"] == 4
    assert any("next page" in warning for warning in result["warnings"])
    assert "opaque-pagination-cursor" not in json.dumps(result)
    assert "another-cursor" not in json.dumps(result)
    source, imported, affected, group, site, org = result["results"]["Object"]
    assert imported["name"] == importer.EVENT
    assert values(imported, "event-id") == ["event-42"]
    assert values(imported, "action-id") == ["user_access_granted"]
    assert values(imported, "event-time-raw") == ["2025-02-27T18:50:12.281Z"]
    assert values(imported, "event-time") == ["2025-02-27T18:50:12.281000+00:00"]
    assert values(imported, "organization-id") == ["org-1"]
    assert values(imported, "site-id") == ["site-2"]
    assert values(imported, "site") == ["example.atlassian.net"]
    assert values(imported, "actor-id") == ["account-17"]
    assert attrs(imported, "actor-email")[0]["type"] == "email-src"
    assert values(imported, "auth-type") == ["api-token"]
    assert values(imported, "token-id") == ["token-id"]
    assert values(imported, "on-behalf-of-email") == ["delegate@example.org"]
    assert values(imported, "app-name") == ["Workflow"]
    assert values(imported, "source-address") == ["2001:0db8::3"]
    assert values(imported, "ip-src") == ["2001:db8::3"]
    assert values(imported, "country") == ["France"]
    assert values(imported, "message-format") == ["example-format"]
    assert json.loads(values(imported, "raw-record")[0]) == event
    assert not values(source, "attachment")
    assert links(imported, "extracted-from")[0]["referenced_uuid"] == source["uuid"]
    assert [(ref["comment"], ref["referenced_uuid"]) for ref in links(imported, "contains")] == [
        ("attributes.context[0]", affected["uuid"]),
        ("attributes.context[1]", group["uuid"]),
        ("attributes.container[0]", site["uuid"]),
        ("attributes.container[1]", org["uuid"]),
    ]
    assert values(affected, "entity-role") == ["context"]
    assert values(affected, "entity-email") == ["member@example.org"]
    assert values(site, "entity-role") == ["container"]
    assert values(site, "entity-id") == ["site-2"]
    assert not any(a["to_ids"] for obj in (imported, affected, group, site, org) for a in obj["Attribute"])


def test_stream_pages_retain_processing_time_and_envelope_scope():
    event = record(processedAt="2025-02-27T18:50:15.000Z", context=[], container=None)
    del event["links"]
    result = submitted({"data": [event], "links": {"self": "/admin/v1/orgs/org-3/events-stream"}})
    _, imported = result["results"]["Object"]
    assert values(imported, "processed-time-raw") == ["2025-02-27T18:50:15.000Z"]
    assert values(imported, "organization-id") == ["org-3"]
    assert not result["warnings"]


def test_native_ids_deduplicate_only_identical_records_in_one_organization():
    first = record()
    other = record()
    other["links"]["self"] = other["links"]["self"].replace("org-1", "org-2")
    result = submitted([first, first, other])
    _, one, two, *_ = result["results"]["Object"]
    assert one["uuid"] != two["uuid"]
    assert result["summary"]["duplicate_records"] == 1
    rerun = submitted({"data": first})["results"]["Object"][1]
    assert one["uuid"] == rerun["uuid"]
    assert (
        "Conflicting records share the same organization" in submitted([record(), record(action="access_revoked")])[
            "error"
        ]
    )


def test_atlassian_admin_csv_split_utc_columns_multiline_and_gzip():
    header = ["Date", "Time (UTC)", "Activity", "Actor", "App", "Location", "IP address", "Site", "Details"]
    row = [
        "2026-04-02",
        "12:06:11.234",
        "User added to site",
        "admin@example.org",
        "Jira",
        "France",
        "203.0.113.5",
        "example.atlassian.net",
        'Group "site users",\naccess granted',
    ]
    raw = gzip.compress(csv_file(header, row))
    result = submitted(
        raw,
        filename="C:\\audit\\organization.csv.gz",
        config={
            "include_source": True,
            "organization_id": "org-7",
            "site": "fallback-site",
            "csv_utc_offset": "-05:00",
        },
    )
    source, imported = result["results"]["Object"]
    assert result["summary"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["summary"]["format"] == "csv"
    assert result["warnings"] == []
    assert values(source, "filename") == ["organization.csv.gz"]
    assert base64.b64decode(attrs(source, "attachment")[0]["data"]) == raw
    assert values(imported, "event-time") == ["2026-04-02T12:06:11.234000+00:00"]
    assert values(imported, "organization-id") == ["org-7"]
    assert values(imported, "site") == ["example.atlassian.net"]
    assert values(imported, "actor-email") == ["admin@example.org"]
    assert values(imported, "activity") == ["User added to site"]
    assert json.loads(values(imported, "raw-record")[0]) == dict(zip(header, row, strict=True))
    assert links(imported, "extracted-from")[0]["comment"] == "CSV row ending at line 3"


@pytest.mark.parametrize(
    ("reported", "config", "utc"),
    [
        ("2026-04-02 08:07:00", {}, None),
        ("2026-04-02 08:07:00", {"csv_utc_offset": "-05:00"}, "2026-04-02T13:07:00+00:00"),
        ("Apr 2, 2026 — 08:07 GMT+2", {}, "2026-04-02T06:07:00+00:00"),
        ("2026-04-02T08:07:12.123456789+02:00", {}, "2026-04-02T06:07:12.123456+00:00"),
        ("2026-04-02T08:07:00-00:00", {"csv_utc_offset": "+00:00"}, None),
        ("2026-04-02", {"csv_utc_offset": "+00:00"}, None),
    ],
)
def test_csv_time_uses_reported_or_supplied_zone_and_preserves_uncertainty(reported, config, utc):
    raw = csv_file(
        ["Date and Time", "Activity", "Actor", "IP address"], [reported, "Sign-in", "Atlassian system", "Unavailable"]
    )
    result = submitted(raw, config={"site": "example.atlassian.net", **config})
    _, event = result["results"]["Object"]
    assert values(event, "event-time-raw") == [reported]
    assert values(event, "event-time") == ([utc] if utc else [])
    assert result["summary"]["csv_timestamps_without_utc"] == int(not utc)
    assert bool(result["warnings"]) == (not utc)
    assert values(event, "site") == ["example.atlassian.net"]
    assert values(event, "source-address") == ["Unavailable"]
    assert not values(event, "ip-src")


def test_large_row_fragments_preserve_the_original_record():
    event = record(context=[{"id": "large", "attributes": {"payload": r" x \ y " * 8000}}])
    _, imported, *_ = submitted(event)["results"]["Object"]
    assert not values(imported, "raw-record")
    fragments = attrs(imported, "raw-record-fragment")
    assert len(fragments) > 1
    assert json.loads("".join(json.loads(a["value"]) for a in fragments)) == event
    assert all(len(a["value"]) <= 32768 for a in fragments)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"data": [], "meta": {"next": "cursor"}}, "has a next page"),
        ({"data": {"id": "project", "type": "projects"}}, "type events"),
        (record(time="2026-04-02 12:06:11"), "known UTC offset"),
        (record(context={"id": "account"}), "attributes.context must be an array"),
        (record(context=[{"type": "site"}]), "attributes.context[0].id must"),
        (b"Date,Activity, activity\n2026-04-02,Access Added,Action\n", "with unique headers"),
        (b"Date,Activity\n2026-04-02,Access Added,Extra\n", "wrong number of columns"),
        (b'{"data":[],"data":[]}', "Duplicate JSON key"),
        (b"\x1f\x8bgarbled", "Unable to decode"),
    ],
)
def test_rejects_unrelated_or_malformed_exports(document, message):
    result = submitted(document)
    assert message in result["error"]
    assert "results" not in result


def test_entity_budget(monkeypatch):
    monkeypatch.setattr(importer, "MAX_ENTITIES", 1)
    assert "audit entities" in submitted(record())["error"]
