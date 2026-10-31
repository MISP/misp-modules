import base64

import pytest

from misp_modules.modules.import_mod import email_import


@pytest.mark.parametrize(
    "subject, expected",
    [
        ("[CASE-123] RE: malware", "[CASE-123] malware"),
        ("[TLP:AMBER] RE: incident", "[TLP:AMBER] incident"),
        ("[CASE-123] [TLP:AMBER] RE: Fwd: incident", "[CASE-123] [TLP:AMBER] incident"),
        ("RE: [CASE-123] Fwd: [TLP:AMBER] AW[2]: incident", "[CASE-123] [TLP:AMBER] incident"),
        ("[CASE-123]RE:malware", "[CASE-123]malware"),
        ("RE: malware", "malware"),
        (" Fwd: RE: malware", "malware"),
        ("AW[2]: WG: incident", "incident"),
        ("re[12]: fW: SV: TR: RV: VS: incident", "incident"),
        ("[CASE-123] malware", "[CASE-123] malware"),
        ("[TLP:AMBER]", "[TLP:AMBER]"),
        ("[RE: malware]", "[RE: malware]"),
        ("[CASE-123] report RE: malware", "[CASE-123] report RE: malware"),
        ("report RE: malware", "report RE: malware"),
        ("Reactor: incident", "Reactor: incident"),
        ("RE: [CASE-123]", "[CASE-123]"),
        ("RE: Fwd:", ""),
        ("", ""),
    ],
)
def test_remove_common_subject_markers(subject, expected):
    assert email_import.remove_common_subject_markers(subject) == expected


@pytest.mark.parametrize(
    "subject, config, expected",
    [
        ("[CASE-123] RE: malware", {"remove_subject_markers": "true"}, "[CASE-123] malware"),
        ("[TLP:AMBER] RE: incident", {"remove_subject_markers": "yes"}, "[TLP:AMBER] incident"),
        ("RE: Fwd:", {"remove_subject_markers": "true"}, "RE: Fwd:"),
        ("[CASE-123] RE: malware", {}, "[CASE-123] RE: malware"),
        ("[CASE-123] RE: malware", {"remove_subject_markers": "false"}, "[CASE-123] RE: malware"),
    ],
)
def test_imported_subject(subject, config, expected):
    message = f"From: sender@example.test\r\nTo: analyst@example.test\r\nSubject: {subject}\r\n\r\nIncident report.\r\n"
    result = email_import.dict_handler({"data": base64.b64encode(message.encode()).decode(), "config": config})
    email_object = result["results"]["Object"][0]
    subjects = [a["value"] for a in email_object["Attribute"] if a["object_relation"] == "subject"]
    assert subjects == [expected]
