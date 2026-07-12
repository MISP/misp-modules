import base64
from email.message import EmailMessage

from misp_modules.modules.import_mod.email_import import dict_handler


def _query(message):
    return dict_handler({
        "data": base64.b64encode(message.as_bytes()).decode(),
        "config": {"extract_forwarded_emails": "true"},
    })["results"]["Object"]


def _email_subjects(objects):
    subjects = []
    for obj in objects:
        if obj.get("name") != "email":
            continue
        for attribute in obj.get("Attribute", []):
            if attribute.get("object_relation") == "subject":
                subjects.append(attribute.get("value"))
    return subjects


def test_extracts_outlook_inline_forwarded_email_from_plain_text():
    message = EmailMessage()
    message["From"] = "Security <security@example.org>"
    message["To"] = "Analyst <analyst@example.org>"
    message["Subject"] = "FW: Are you in the office?"
    message.set_content("""The mail followed by the forwarded mail.

Greetings
Jens
________________________________
From: Name <mail@gmail.com>
Sent: Friday, 20 February 2026 11:43
To: Other Name <other@example.org>
Subject: Are you in the office?

Can you confirm?
""")

    objects = _query(message)

    assert _email_subjects(objects).count("FW: Are you in the office?") == 1
    assert "Are you in the office?" in _email_subjects(objects)
    assert len([obj for obj in objects if obj.get("name") == "email"]) == 2
    assert any(ref.get("relationship_type") == "includes" for ref in objects[0].get("ObjectReference", []))


def test_extracts_message_rfc822_forwarded_email_attachment():
    forwarded = EmailMessage()
    forwarded["From"] = "Sender <sender@example.org>"
    forwarded["To"] = "Recipient <recipient@example.org>"
    forwarded["Subject"] = "Attached phishing email"
    forwarded.set_content("Please review the link")

    carrier = EmailMessage()
    carrier["From"] = "Security <security@example.org>"
    carrier["To"] = "Analyst <analyst@example.org>"
    carrier["Subject"] = "Fwd attachment"
    carrier.set_content("Forwarded as attachment")
    carrier.add_attachment(forwarded, subtype="rfc822", filename="forwarded.eml")

    objects = _query(carrier)

    assert "Attached phishing email" in _email_subjects(objects)
    assert len([obj for obj in objects if obj.get("name") == "email"]) == 2


def test_extracts_outlook_inline_forwarded_email_from_html():
    message = EmailMessage()
    message["From"] = "Security <security@example.org>"
    message["To"] = "Analyst <analyst@example.org>"
    message["Subject"] = "FW: HTML"
    message.add_alternative("""<html><body><p>Hello,</p>
<div><hr><div id="divRplyFwdMsg"><font><b>From:</b> Name &lt;mail@gmail.com&gt;<br>
<b>Sent:</b> Friday, 20 February 2026 11:43<br>
<b>To:</b> Other Name &lt;other@example.org&gt;<br>
<b>Subject:</b> Are you in the office?</font></div>
<div>Can you confirm?</div></div></body></html>""", subtype="html")

    objects = _query(message)

    assert "Are you in the office?" in _email_subjects(objects)
    assert len([obj for obj in objects if obj.get("name") == "email"]) == 2
