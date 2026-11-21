# Cited intelligence briefing export

Export an event through **Cited Intelligence Briefing Export** in MISP, or call
`POST /query` with `module` set to `intelligence_briefing_export` and one event
in `data`. The response contains a base64-encoded Markdown file, a validation
summary, and warnings. The MISP export module requests Event Reports and
Analyst Data without attachment content and accepts standard and legacy event
envelopes.

## Author the briefing in MISP

1. Install the `intelligence-judgment` object template on the authoring instance.
2. Add one judgment object per key judgment. Record its confidence as `low`,
   `moderate`, or `high`. Add the basis for confidence and one or more
   alternatives. An explicit assessment of why no credible alternative was
   identified can be recorded in the alternatives field.
3. Link each judgment to evidence using an Object Relationship or Analyst
   Relationship. Use `supported-by`, `based-on`, `cites`, `references`, or
   `contradicted-by` from the judgment to evidence. Use `supports` or
   `contradicts` for links in the other direction.
4. Reference each judgment in the Event Report with `@[object](UUID)`.
   Native object and attribute references in the narrative also become
   numbered citations. Add Analyst Notes and Opinions to the report or its
   judgments for commentary.

Evidence can be a visible attribute, object, or another Event Report supplied
with the same event. The source appendix lists citation anchors and MISP UUIDs.
When a cited INTREP has matching `intelligence-source-assessment` objects, the
export includes their ratings and evaluation. An assessment's `related-report`
can match the INTREP's UUID or unique `report-id`. Source-assessment confidence
and Analyst Opinion agreement scores appear separately from judgment confidence.

One visible Event Report is selected automatically. If several exist, the
export uses the sole report that references a judgment. API callers can supply
`config.report_uuid` to disambiguate other cases.

## Review and release

The initial export is a draft. Its release checks flag missing judgments,
confidence, alternatives, and missing or unresolved evidence citations. The
briefing fingerprint covers the text and the supplied cited evidence
fields, including metadata for attachment attributes. It represents the
contents of the export, with the underlying attachment kept at its source.

After reviewing the brief, attach an Analyst Opinion to the selected Event
Report. Set its comment to `Approve briefing sha256:<digest>` using the
fingerprint printed in the file. The opinion needs an author and a UUID.
Export again to check the approval against the current version. The result is
marked **REVIEWED** when the fingerprint matches and release checks pass.
Changes to the briefing or cited evidence require approval of the new
fingerprint. Set `config.require_reviewed` to `true` on the API to require
reviewed output. Failed checks return the summary and warnings.

MISP remains responsible for export permissions and dissemination. The file
carries applicable TLP, PAP, and classification tags from the inputs it uses.
Source evidence is indexed by UUID. Raw attachments and unrestricted attribute
values stay with the original event. The exporter runs offline and renders
report prose as text, with local links for resolved citations.

- [MISP Event Reports](https://www.misp-project.org/2020/10/08/Event-Reports.html/)
- [MISP Analyst Data](https://www.misp-project.org/2024/03/06/MISP.2.4.186.released.html/)
- [ODNI analytic standards](https://www.intelligence.gov/mission/our-values/objectivity)
