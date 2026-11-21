"""Build an offline intelligence briefing from an authorized MISP event export."""

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from html import escape

from misp_modules.lib.indicator_list import boolean

JUDGMENT = "intelligence-judgment"
INTREP = "intelligence-report"
ASSESSMENT = "intelligence-source-assessment"
APPROVAL = "Approve briefing sha256:"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)
REPORT_REF = re.compile(r"(?<!\\)@!?\[(attribute|object)\]\(([^()\r\n]*)\)", re.IGNORECASE)
MARKDOWN = re.compile(r"([\\\x60*_[\]{}()#+.!|~=-])")
CITATION_TYPES = {
    "supported-by": "Supporting evidence",
    "based-on": "Supporting evidence",
    "cites": "Cited evidence",
    "references": "Cited evidence",
    "contradicted-by": "Contrary evidence",
}
REVERSE_TYPES = {"supports": "Supporting evidence", "contradicts": "Contrary evidence"}
SOURCE_FIELDS = {
    "source-id": "Source ID",
    "source-type": "Source type",
    "source-summary": "Source summary",
    "source-reliability": "Source reliability",
    "information-credibility": "Information credibility",
    "confidence": "Source assessment confidence",
    "evaluation": "Source evaluation",
}
INTREP_FIELDS = {
    "report-id": "Report ID",
    "reporting-unit": "Reporting unit",
    "classification": "Classification",
    "handling-instructions": "Handling instructions",
}


@dataclass(frozen=True)
class Record:
    kind: str
    data: dict
    parent: str = ""


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _id(value):
    value = _text(value)
    return value.lower() if UUID.fullmatch(value) else ""


def _literal(value):
    """Render source text as text, including markup embedded in a MISP record."""
    text = " ".join(_text(value).splitlines())
    text = "".join(char if char.isprintable() else " " for char in text)
    return MARKDOWN.sub(r"\\\1", escape(text, quote=False))


def _items(container, name):
    values = container.get(name, [])
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise ValueError(f"{name} must be a list of objects.")
    for item in values:
        record = item.get(name, item)
        if not isinstance(record, dict):
            raise ValueError(f"{name} contains an invalid record.")
        if not boolean(record.get("deleted"), "deleted"):
            yield record


def _event(data):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise ValueError("Provide exactly one authorized MISP event in data.")
    core = data.get("Event", data)
    if not isinstance(core, dict):
        raise ValueError("Event must be an object.")
    event = {**data, **core}
    if boolean(event.get("deleted"), "deleted"):
        raise ValueError("The selected event is deleted.")
    return event


def _fields(obj):
    fields = defaultdict(list)
    for attribute in _items(obj, "Attribute"):
        relation, value = _text(attribute.get("object_relation")), _text(attribute.get("value"))
        if relation and value and attribute.get("type") not in ("attachment", "malware-sample"):
            fields[relation].append(value)
    return fields


def _one(fields, name):
    values = fields.get(name, ())
    return values[0] if len(values) == 1 else ""


def _source_revision(item):
    # Compare supplied evidence revisions without putting unrestricted attribute values in the brief.
    fields = (
        "uuid",
        "name",
        "type",
        "object_relation",
        "value",
        "content",
        "timestamp",
        "distribution",
        "sharing_group_id",
    )
    revision = {key: item.data[key] for key in fields if key in item.data}
    if item.kind == "Object":
        revision["Attribute"] = sorted(
            json.dumps({key: attr[key] for key in fields if key in attr}, sort_keys=True)
            for attr in _items(item.data, "Attribute")
        )
    return revision


class EventIndex:
    def __init__(self, event):
        self.event = event
        self.records = {}
        self.notes = defaultdict(list)
        self.opinions = defaultdict(list)
        self.edges = defaultdict(list)
        self.assessments = {}
        self.report_ids = Counter()
        self.event_id = _id(event.get("uuid"))
        self._read_analyst_data(event, self.event_id)
        for kind in ("Attribute", "Object", "EventReport"):
            for data in _items(event, kind):
                parent = self._add(kind, data, self.event_id)
                if kind == "Object":
                    for attribute in _items(data, "Attribute"):
                        self._add("Attribute", attribute, parent)
                    self._read_object_links(data, parent)
                    if data.get("name") == ASSESSMENT and parent:
                        self.assessments[parent] = _fields(data)
                    if data.get("name") == INTREP:
                        report_id = _one(_fields(data), "report-id")
                        if report_id:
                            self.report_ids[report_id] += 1

    def _add(self, kind, data, parent):
        uuid = _id(data.get("uuid"))
        if uuid:
            record = Record(kind, data, parent)
            if uuid in self.records and self.records[uuid] != record:
                raise ValueError("Conflicting MISP records share a UUID in the selected event.")
            self.records[uuid] = record
        self._read_analyst_data(data, uuid)
        return uuid

    def _read_object_links(self, obj, owner):
        if not owner:
            return
        for link in _items(obj, "ObjectReference"):
            self._link(owner, _id(link.get("referenced_uuid")), _text(link.get("relationship_type")).lower())

    def _read_analyst_data(self, owner, owner_id):
        for kind, collection in (("Note", self.notes), ("Opinion", self.opinions)):
            for item in _items(owner, kind):
                target = _id(item.get("object_uuid")) if "object_uuid" in item else owner_id
                if target:
                    collection[target].append(item)
        for link in _items(owner, "Relationship"):
            origin = _id(link.get("object_uuid")) if "object_uuid" in link else owner_id
            self._link(origin, _id(link.get("related_object_uuid")), _text(link.get("relationship_type")).lower())

    def _link(self, origin, target, relation):
        if relation in CITATION_TYPES and origin:
            self.edges[origin].append((CITATION_TYPES[relation], target))
        if relation in REVERSE_TYPES and target:
            self.edges[target].append((REVERSE_TYPES[relation], origin))

    def judgment(self, uuid):
        item = self.records.get(uuid)
        return item is not None and item.kind == "Object" and item.data.get("name") == JUDGMENT

    def select_report(self, requested):
        if requested not in (None, ""):
            uuid = _id(requested)
            item = self.records.get(uuid)
            if item is None or item.kind != "EventReport":
                raise ValueError("report_uuid must identify a visible Event Report in the selected event.")
            return uuid, item.data
        reports = [(uuid, item.data) for uuid, item in self.records.items() if item.kind == "EventReport"]
        if len(reports) == 1:
            return reports[0]
        # MISP's event export menu has no per-download report UUID selector.
        composed = [
            (uuid, report)
            for uuid, report in reports
            if any(
                kind.lower() == "object" and self.judgment(_id(ref))
                for kind, ref in REPORT_REF.findall(_text(report.get("content")))
            )
        ]
        if len(composed) == 1:
            return composed[0]
        if not reports:
            raise ValueError("The event contains no visible Event Report with a UUID.")
        raise ValueError("Several Event Reports are available. Select one with config.report_uuid.")

    def linked_assessments(self, uuid, report_id):
        identifiers = {uuid}
        if report_id and self.report_ids[report_id] == 1:
            identifiers.add(report_id)
        for assessment, fields in sorted(self.assessments.items()):
            references = {_id(value) or value for value in fields.get("related-report", ())}
            if references & identifiers:
                yield assessment, fields


class Briefing:
    def __init__(self, index, report_uuid, report):
        self.index = index
        self.report_uuid = report_uuid
        self.report = report
        self.title = _text(report.get("name")) or "Intelligence briefing"
        self.sources = {}
        self.problems = []
        self.markings = set()
        self.judgments = {}
        self._mark(index.event)
        self._mark(report)

    def _mark(self, item):
        for tag in _items(item, "Tag"):
            name = _text(tag.get("name"))
            if name.lower().startswith(("tlp:", "pap:", "classification:")):
                self.markings.add(name)

    def _mark_record(self, uuid):
        item = self.index.records[uuid]
        self._mark(item.data)
        if item.parent in self.index.records:
            self._mark(self.index.records[item.parent].data)

    def _cite(self, uuid, expected_kind=None):
        item = self.index.records.get(uuid)
        if (
            item is None
            or (expected_kind and expected_kind != item.kind)
            or self.index.judgment(uuid)
            or uuid == self.report_uuid
        ):
            return None
        if uuid not in self.sources:
            self.sources[uuid] = f"S{len(self.sources) + 1}"
            self._mark_record(uuid)
        label = self.sources[uuid]
        return f"[{label}](#{label.lower()})"

    def _report_text(self):
        text = _text(self.report.get("content"))
        for kind, ref in REPORT_REF.findall(text):
            uuid = _id(ref)
            if kind.lower() == "object" and self.index.judgment(uuid) and uuid not in self.judgments:
                self.judgments[uuid] = f"J{len(self.judgments) + 1}"

        def replacement(match):
            kind, ref = match.groups()
            uuid = _id(ref)
            if kind.lower() == "object" and uuid in self.judgments:
                label = self.judgments[uuid]
                return f"[{label}](#{label.lower()})"
            citation = self._cite(uuid, kind.title())
            if citation:
                return citation
            self.problems.append(
                f"Event Report contains an unresolved {kind.lower()} reference" + (f" ({uuid})" if uuid else "") + "."
            )
            return "**Unresolved citation**"

        lines = []
        for raw_line in text.splitlines():
            parts, offset = [], 0
            for match in REPORT_REF.finditer(raw_line):
                parts.extend((_literal_fragment(raw_line[offset : match.start()]), replacement(match)))
                offset = match.end()
            parts.append(_literal_fragment(raw_line[offset:]))
            lines.append("".join(parts).strip())
        return "\n".join(lines) or "The Event Report contains no narrative."

    def _analyst_comments(self, uuid):
        entries = []
        for role, item, field in self._comments(uuid):
            message = _text(item.get(field))
            if role == "Opinion":
                score = str(item.get("opinion", ""))
                if re.fullmatch(r"[0-9]{1,3}", score) and int(score) <= 100:
                    message = f"Agreement {int(score)}/100" + (f" — {message}" if message else "")
            if not message:
                continue
            self._mark(item)
            author = _literal(item.get("authors")) or "Author unspecified"
            entries.append(f"- {role} by {author} — {_literal(message)}")
        return entries

    def _comments(self, uuid):
        seen = set()
        for role, collection, field in (
            ("Note", self.index.notes, "note"),
            ("Opinion", self.index.opinions, "comment"),
        ):
            for item in sorted(collection[uuid], key=lambda row: (_id(row.get("uuid")), _text(row.get(field)))):
                message = _text(item.get(field))
                if role == "Opinion" and message.startswith(APPROVAL):
                    continue
                key = (role, _id(item.get("uuid")), _text(item.get("authors")), message, str(item.get("opinion", "")))
                if key not in seen:
                    seen.add(key)
                    yield role, item, field

    def _judgment(self, uuid, label):
        self._mark_record(uuid)
        fields = _fields(self.index.records[uuid].data)
        title = _literal(_one(fields, "title"))
        judgment = _one(fields, "judgment")
        confidence = _one(fields, "confidence").lower()
        alternatives = fields.get("alternative", [])
        lines = [f"### {label}", "", f"{title} — {_literal(judgment)}" if title else _literal(judgment)]
        lines.append(f"- MISP judgment UUID {uuid}")
        if not judgment:
            self.problems.append(f"{label} needs one nonempty judgment.")
        if confidence not in {"low", "moderate", "high"}:
            self.problems.append(f"{label} needs a confidence level of low, moderate, or high.")
            confidence = "Unspecified"
        lines.append(f"- Confidence **{confidence}**")
        rationale = _one(fields, "confidence-rationale")
        if rationale:
            lines.append(f"- Confidence rationale — {_literal(rationale)}")
        links = defaultdict(list)
        for role, ref in sorted(set(self.index.edges[uuid])):
            citation = self._cite(ref)
            if citation:
                links[role].append(citation)
            else:
                self.problems.append(
                    f"{label} has an unresolved evidence citation" + (f" ({ref})" if ref else "") + "."
                )
        if not links:
            self.problems.append(f"{label} needs at least one resolvable evidence citation.")
        for role, citations in links.items():
            lines.append(f"- {role} — {', '.join(citations)}")
        if alternatives:
            lines.extend(f"- Alternative — {_literal(alternative)}" for alternative in alternatives)
        else:
            self.problems.append(f"{label} needs an alternative or a recorded assessment of alternatives.")
        lines.extend(self._analyst_comments(uuid))
        return "\n".join(lines)

    def _source(self, uuid, label):
        item = self.index.records[uuid]
        name = _text(item.data.get("name" if item.kind != "Attribute" else "type"))
        lines = [f"### {label}", "", f"- MISP {item.kind}" + (f" — {_literal(name)}" if name else ""), f"- UUID {uuid}"]
        if item.kind == "Object" and name == INTREP:
            fields = _fields(item.data)
            lines.extend(_field_lines(fields, INTREP_FIELDS))
            for assessment, values in self.index.linked_assessments(uuid, _one(fields, "report-id")):
                self._mark_record(assessment)
                lines.append(f"- INTREP source assessment {assessment}")
                lines.extend(_field_lines(values, SOURCE_FIELDS, indent="  "))
        if item.kind == "Object" and name == ASSESSMENT:
            lines.extend(_field_lines(_fields(item.data), SOURCE_FIELDS))
        return "\n".join(lines)

    def _approval(self, digest):
        expected = APPROVAL + digest
        for entry in sorted(self.index.opinions[self.report_uuid], key=lambda item: _id(item.get("uuid"))):
            uuid = _id(entry.get("uuid"))
            author = _text(entry.get("authors"))
            if uuid and author and _text(entry.get("comment")) == expected:
                return uuid, author
        return None

    def render(self):
        narrative = self._report_text()
        judgments = [self._judgment(uuid, label) for uuid, label in self.judgments.items()]
        if not judgments:
            self.problems.append("The Event Report needs at least one referenced intelligence judgment.")
        notes = self._analyst_comments(self.report_uuid)
        sources = [self._source(uuid, label) for uuid, label in self.sources.items()]
        sections = [
            f"Event Report UUID {self.report_uuid}",
            "## Event Report\n\n" + narrative,
            "## Key judgments\n\n" + ("\n\n".join(judgments) if judgments else "No judgments selected."),
        ]
        if self.index.event_id:
            sections.insert(0, f"MISP event UUID {self.index.event_id}")
        if notes:
            sections.append("## Analyst commentary\n\n" + "\n".join(notes))
        if sources:
            sections.append("## Sources\n\n" + "\n\n".join(sources))
        if self.markings:
            sections.append(
                "## Handling markings\n\n" + "\n".join(f"- {_literal(mark)}" for mark in sorted(self.markings))
            )
        heading = f"# {_literal(self.title)}"
        content = "\n\n".join(sections) + "\n"
        issues = list(dict.fromkeys(self.problems))
        evidence = {uuid: _source_revision(self.index.records[uuid]) for uuid in self.sources}
        fingerprint = json.dumps(
            [heading, content, evidence, issues], ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        digest = hashlib.sha256(fingerprint.encode("ascii")).hexdigest()
        approval = self._approval(digest)
        warnings = issues.copy()
        if approval is None:
            warnings.append("The Event Report has no analyst approval for this briefing version.")
        status = "reviewed" if not warnings else "draft"
        header = [heading, f"**Status {status.upper()}**", f"Briefing fingerprint **sha256:{digest}**"]
        if approval:
            header.append(f"Recorded analyst approval by {_literal(approval[1])} (Opinion UUID {approval[0]}).")
        if warnings:
            header.append("## Release checks\n\n" + "\n".join(f"- {_literal(warning)}" for warning in warnings))
        summary = {
            "status": status,
            "report_uuid": self.report_uuid,
            "sha256": digest,
            "judgments": len(judgments),
            "sources": len(sources),
            "issues": len(issues),
            "approval_uuid": approval[0] if approval else None,
        }
        return "\n\n".join(header) + "\n\n" + content, summary, warnings


def _literal_fragment(value):
    # Preserve spacing on either side of a native MISP reference.
    leading = value != value.lstrip()
    trailing = value != value.rstrip()
    if not value.strip():
        return " " if value else ""
    return (" " if leading else "") + _literal(value) + (" " if trailing else "")


def _field_lines(fields, names, indent=""):
    for relation, label in names.items():
        for value in fields.get(relation, ()):
            yield f"{indent}- {label} — {_literal(value)}"


def build_briefing(data, requested_report):
    index = EventIndex(_event(data))
    uuid, report = index.select_report(requested_report)
    return Briefing(index, uuid, report).render()
