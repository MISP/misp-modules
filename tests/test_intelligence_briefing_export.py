import base64
import copy
import json

import pytest

from misp_modules.modules.export_mod import intelligence_briefing_export as module

EVENT = "08000000-0000-4000-8000-000000000001"
REPORT = "08000000-0000-4000-8000-000000000002"
OTHER_REPORT = "08000000-0000-4000-8000-000000000003"
JUDGMENT = "08000000-0000-4000-8000-000000000004"
INTREP = "08000000-0000-4000-8000-000000000005"
ASSESSMENT = "08000000-0000-4000-8000-000000000006"
EVIDENCE = "08000000-0000-4000-8000-000000000007"
OUTSIDE = "08000000-0000-4000-8000-000000000008"
REVIEW = "08000000-0000-4000-8000-000000000009"


def reference(kind, uuid):
    return f"@[{kind}]({uuid})"


def field(relation, value, kind="text"):
    return {"object_relation": relation, "value": value, "type": kind}


def event():
    return {
        "uuid": EVENT,
        "Tag": [{"name": "tlp:amber"}],
        "EventReport": [
            {
                "uuid": REPORT,
                "name": "Briefing for analysts",
                "content": f"Context {reference('object', JUDGMENT)} and {reference('attribute', EVIDENCE)}.",
                "Note": [{"object_uuid": REPORT, "authors": "Ira", "note": "Collection was limited to one period."}],
            }
        ],
        "Attribute": [
            {"uuid": EVIDENCE, "type": "filename", "value": "evidence-record.log", "Tag": [{"name": "pap:RED"}]}
        ],
        "Object": [
            {
                "uuid": JUDGMENT,
                "name": "intelligence-judgment",
                "Attribute": [
                    field("title", "Continuity"),
                    field("judgment", "The two observations have a common origin."),
                    field("confidence", "moderate"),
                    field("confidence-rationale", "The evidence has consistent metadata."),
                    field("alternative", "The apparent similarity is coincidental."),
                ],
                "ObjectReference": [{"referenced_uuid": INTREP, "relationship_type": "supported-by"}],
                "Opinion": [{"object_uuid": JUDGMENT, "authors": "Morgan", "opinion": "75"}],
            },
            {
                "uuid": INTREP,
                "name": "intelligence-report",
                "Attribute": [
                    field("report-id", "REPORT-42"),
                    field("classification", "TLP:AMBER"),
                    field("raw-report", "DO NOT EXPORT THIS", "attachment"),
                ],
            },
            {
                "uuid": ASSESSMENT,
                "name": "intelligence-source-assessment",
                "Attribute": [
                    field("related-report", "REPORT-42"),
                    field("source-id", "Source EX-42"),
                    field("source-reliability", "A - Completely reliable"),
                    field("information-credibility", "2 - Probably true"),
                    field("confidence", "high"),
                    field("raw-assessment", "DO NOT EXPORT THIS", "attachment"),
                ],
            },
        ],
        "Relationship": [
            {"object_uuid": EVIDENCE, "related_object_uuid": JUDGMENT, "relationship_type": "contradicts"},
            {"object_uuid": JUDGMENT, "related_object_uuid": OUTSIDE, "relationship_type": "related-to"},
        ],
    }


def invoke(data, **config):
    return module.handler(json.dumps({"data": data, "config": config}))


def text(result):
    assert "error" not in result, result
    return base64.b64decode(result["data"], validate=True).decode("utf-8")


def approve(data, digest, **changes):
    data["EventReport"][0].setdefault("Opinion", []).append(
        {
            "uuid": REVIEW,
            "object_uuid": REPORT,
            "authors": "Reviewer",
            "opinion": 100,
            "comment": f"Approve briefing sha256:{digest}",
            **changes,
        }
    )


def test_exports_natively_shaped_event_with_judgment_links_and_source_assessment():
    result = invoke([{"Event": event()}])
    doc = text(result)
    assert result["summary"]["status"] == "draft"
    assert result["summary"]["judgments"] == 1
    assert result["summary"]["sources"] == 2
    assert result["summary"]["issues"] == 0
    assert "[J1](#j1)" in doc and "### J1" in doc
    assert "Confidence **moderate**" in doc
    assert "Alternative — The apparent similarity is coincidental" in doc
    assert "Supporting evidence — [S2](#s2)" in doc
    assert "Contrary evidence — [S1](#s1)" in doc
    assert f"UUID {INTREP}" in doc and f"UUID {EVIDENCE}" in doc
    assert "Source assessment confidence — high" in doc
    assert "Source reliability — A" in doc
    assert "Information credibility — 2" in doc
    assert "Note by Ira" in doc and "Opinion by Morgan — Agreement 75/100" in doc
    assert "tlp:amber" in doc and "pap:RED" in doc
    assert "DO NOT EXPORT THIS" not in doc and "evidence-record.log" not in doc
    assert invoke([{"Event": event()}]) == result


def test_supports_legacy_event_data_and_selects_only_the_briefing_report():
    data = event()
    reports = data.pop("EventReport")
    reports.append({"uuid": OTHER_REPORT, "content": "OTHER REPORT CONTEXT", "name": "Routine report"})
    objects = data.pop("Object")
    output = text(invoke({"Event": data, "EventReport": reports, "Object": objects}))
    assert f"Event Report UUID {REPORT}" in output
    assert "OTHER REPORT CONTEXT" not in output


def test_approval_is_bound_to_report_and_current_evidence_revision():
    data = event()
    first = invoke(data)
    assert "data" not in invoke(data, require_reviewed=True)
    approve(data, first["summary"]["sha256"])
    reviewed = invoke(data, require_reviewed=True)
    assert reviewed["summary"]["sha256"] == first["summary"]["sha256"]
    assert reviewed["summary"]["approval_uuid"] == REVIEW
    assert reviewed["summary"]["status"] == "reviewed"
    assert "Recorded analyst approval by Reviewer" in text(reviewed)
    assert reviewed["warnings"] == []
    data["Attribute"][0]["value"] = "changed-evidence.log"
    changed = invoke(data)
    assert changed["summary"]["sha256"] != first["summary"]["sha256"]
    assert changed["summary"]["status"] == "draft"
    assert "data" not in invoke(data, require_reviewed=True)


@pytest.mark.parametrize(
    "changes", [{"object_uuid": OUTSIDE}, {"authors": ""}, {"deleted": "1"}, {"comment": "Great work"}]
)
def test_nonmatching_opinions_do_not_approve_a_brief(changes):
    data = event()
    digest = invoke(data)["summary"]["sha256"]
    approve(data, digest, **changes)
    assert invoke(data)["summary"]["status"] == "draft"
    assert "data" not in invoke(data, require_reviewed=True)


def test_flags_missing_and_unresolved_citations_even_with_a_matching_approval():
    data = event()
    data["Object"][0]["ObjectReference"] = [
        {"referenced_uuid": OUTSIDE, "relationship_type": "supported-by"},
        {"referenced_uuid": INTREP, "relationship_type": "references", "deleted": "1"},
    ]
    data["Relationship"].clear()
    data["Object"][0]["Attribute"] = [field("judgment", "Claim with gaps")]
    result = invoke(data)
    assert result["summary"]["issues"] == 4
    assert any("unresolved evidence citation" in warning for warning in result["warnings"])
    assert any("at least one resolvable evidence" in warning for warning in result["warnings"])
    assert any("confidence level" in warning for warning in result["warnings"])
    assert any("alternative" in warning for warning in result["warnings"])
    assert "Release checks" in text(result)
    approve(data, result["summary"]["sha256"])
    refused = invoke(data, require_reviewed=True)
    assert refused["summary"]["approval_uuid"] == REVIEW
    assert refused["summary"]["status"] == "draft" and "data" not in refused


def test_deleted_or_wrong_type_report_citations_are_unresolved():
    data = event()
    data["Attribute"][0]["deleted"] = True
    data["EventReport"][0]["content"] += f" {reference('attribute', INTREP)}"
    result = invoke(data)
    assert sum("unresolved attribute reference" in warning for warning in result["warnings"]) == 2
    assert "**Unresolved citation**" in text(result)


def test_removing_an_unresolved_reference_requires_a_new_review():
    data = event()
    links = data["Object"][0]["ObjectReference"]
    links.append({"referenced_uuid": OUTSIDE, "relationship_type": "references"})
    draft = invoke(data)
    approve(data, draft["summary"]["sha256"])
    assert invoke(data)["summary"]["approval_uuid"] == REVIEW
    links.pop()
    repaired = invoke(data)
    assert repaired["summary"]["issues"] == 0
    assert repaired["summary"]["sha256"] != draft["summary"]["sha256"]
    assert repaired["summary"]["status"] == "draft"


def test_ambiguous_reports_require_explicit_selection():
    data = event()
    data["EventReport"].append(
        {"uuid": OTHER_REPORT, "name": "Another briefing", "content": reference("object", JUDGMENT)}
    )
    assert "report_uuid" in invoke(data)["error"]
    result = invoke(data, report_uuid=OTHER_REPORT)
    assert text(result).startswith("# Another briefing")
    assert result["summary"]["report_uuid"] == OTHER_REPORT
    assert "visible Event Report" in invoke(data, report_uuid=OUTSIDE)["error"]


def test_unrelated_objects_and_markup_are_not_rendered_as_briefing_content():
    data = event()
    data["EventReport"][0]["content"] += "\n![tracking](https://example.test/image)\n<script>name</script>"
    unrelated = copy.deepcopy(data["Object"][0])
    unrelated["uuid"] = OUTSIDE
    unrelated["Attribute"] = [field("judgment", "UNRELATED CLAIM")]
    data["Object"].append(unrelated)
    doc = text(invoke(data))
    assert "UNRELATED CLAIM" not in doc
    assert "<script>" not in doc and "&lt;script&gt;" in doc
    assert r"\!\[tracking\]" in doc
    assert "![tracking]" not in doc


def test_no_structured_judgment_produces_a_draft_without_inferred_claims():
    data = event()
    data["EventReport"][0]["content"] = "A free-form analyst narrative."
    result = invoke(data)
    assert result["summary"]["judgments"] == 0
    assert "No judgments selected." in text(result)
    assert any("referenced intelligence judgment" in warning for warning in result["warnings"])


def test_introspection_and_invalid_request():
    meta = module.version()
    assert meta["module-type"] == ["export"]
    assert meta["fetch_options"]["includeAnalystData"]
    assert not meta["fetch_options"]["includeAttachments"]
    assert module.introspection()["outputFileExtension"] == "md"
    assert module.handler() is False
    assert "error" in invoke([event(), event()])
    assert "error" in module.handler("null")
    assert "error" in invoke(event(), require_reviewed="maybe")
