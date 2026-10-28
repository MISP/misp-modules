"""Exercise inline forwards through the real PyMISP import path."""

import base64
from email.message import EmailMessage

import pytest

from misp_modules.lib.email_forward import MAX_FORWARDS
from misp_modules.modules.import_mod import email_import

PLAIN_FORWARD = """The mail followed by the forwarded mail.

Greetings
Jens
________________________________
From: Name <mail@gmail.com>
Sent: Friday, 20 February 2026 11:43
To: Other Name
Subject: Are you in the office?

Please review https://example.org/review
"""

HTML_FORWARD = """<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
<style type="text/css">P {margin-top:0;margin-bottom:0;}</style></head>
<body dir="ltr"><div id="divtagdefaultwrapper"><p>Hello,</p><p><br></p>
<br><br><div><hr tabindex="-1" style="display:inline-block; width:98%">
<div id="divRplyFwdMsg" dir="ltr"><font face="Calibri, sans-serif">
<b>From:</b> Name &lt;mail@gmail.com&gt;<br>
<b>Sent:</b> Friday, 20 February 2026 11:43<br>
<b>To:</b> Other Name <br>
<b>Subject:</b> Are you in the office?</font><div>&nbsp;</div></div>
<div><div dir="ltr"><div dir="ltr"><br>
<a href="https://example.org/review">Please review</a>
</div></div></div></div></div></body></html>"""


def carrier(body=PLAIN_FORWARD, subtype="plain"):
    message = EmailMessage()
    message["From"] = "Reporter <reporter@example.net>"
    message["To"] = "soc@example.net"
    message["Subject"] = "Fwd: suspicious message"
    message.set_content(body, subtype=subtype)
    return message


def run_import(message, **config):
    return email_import.dict_handler({"data": base64.b64encode(message.as_bytes()), "config": config})["results"][
        "Object"
    ]


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


@pytest.mark.parametrize("body, subtype", [(PLAIN_FORWARD, "plain"), (HTML_FORWARD, "html")])
def test_issue_764_examples(body, subtype):
    message = carrier(body, subtype)
    objects = run_import(message, extract_forwarded_emails="true")
    assert len(objects) == 2
    original, forwarded = objects
    assert values(original, "from") == ["reporter@example.net"]
    assert values(original, "email-body") == [body.strip()]
    assert values(original, "eml")
    assert values(forwarded, "from") == ["mail@gmail.com"]
    assert values(forwarded, "from-display-name") == ["Name"]
    assert values(forwarded, "subject") == ["Are you in the office?"]
    assert values(forwarded, "to-display-name") == ["Other Name"]
    assert not values(forwarded, "to")  # A name must not become an email address.
    assert not values(forwarded, "send-date")  # No timezone was provided.
    assert "Friday, 20 February 2026 11:43" in values(forwarded, "header")[0]
    assert not values(forwarded, "eml")
    assert "Heuristically" in forwarded["comment"]
    assert all(a["to_ids"] is False for a in forwarded["Attribute"])
    reference = original["ObjectReference"][0]
    assert reference["referenced_uuid"] == forwarded["uuid"]
    assert reference["relationship_type"] == "includes"


@pytest.mark.parametrize("setting", [None, "false", "no", "", False])
def test_extraction_disabled_by_default(setting):
    config = {} if setting is None else {"extract_forwarded_emails": setting}
    assert len(run_import(carrier(), **config)) == 1


@pytest.mark.parametrize("setting", ["true", "TRUE", "yes", "y", "t", True])
def test_extraction_truthy_settings(setting):
    assert len(run_import(carrier(), extract_forwarded_emails=setting)) == 2


@pytest.mark.parametrize("marker", ["-------- Forwarded Message --------", "Begin forwarded message:", ""])
def test_mail_to_misp_markers_and_quoted_forward(marker):
    body = "Comment\n" + marker + "\n" + "\n".join("> " + line for line in PLAIN_FORWARD.splitlines()[5:])
    assert len(run_import(carrier(body), extract_forwarded_emails="yes")) == 2


def test_multipart_alternatives_are_not_duplicated():
    message = carrier()
    message.add_alternative(HTML_FORWARD, subtype="html")
    assert len(run_import(message, extract_forwarded_emails="true")) == 2


def test_html_fallback_when_plain_alternative_has_no_forward():
    message = carrier("Please review the HTML version.")
    message.add_alternative(HTML_FORWARD, subtype="html")
    assert len(run_import(message, extract_forwarded_emails="true")) == 2


@pytest.mark.parametrize(
    "body",
    [
        "No forwarded message here.",
        "Begin forwarded message:\nJust a comment.",
        "From: sender@example.org\nOrdinary prose\nTo: recipient@example.org\nSubject: not a header block",
        "From: sender@example.org\nSubject: missing recipient and date",
        "From: A name only\nTo: recipient@example.org\nSubject: No sender address",
        "From: sender@example.org\nTo: recipient@example.org",  # Missing subject.
    ],
)
def test_no_forward_from_insufficient_headers(body):
    assert len(run_import(carrier(body), extract_forwarded_emails="true")) == 1


def test_multiple_forwarded_messages_link_to_carrier():
    objects = run_import(
        carrier(PLAIN_FORWARD + "\n" + PLAIN_FORWARD.replace("mail@gmail.com", "other@example.org")),
        extract_forwarded_emails="true",
    )
    assert len(objects) == 3
    assert values(objects[1], "from") == ["mail@gmail.com"]
    assert values(objects[2], "from") == ["other@example.org"]
    assert {ref["referenced_uuid"] for ref in objects[0]["ObjectReference"]} == {o["uuid"] for o in objects[1:]}


@pytest.mark.parametrize("date", ["Fri, 20 Feb 2026 11:43:00 +0100", "bad date", "Freitag, 20. Februar 2026 11:43"])
def test_dates_are_preserved_and_only_zoned_dates_become_send_dates(date):
    body = PLAIN_FORWARD.replace("Friday, 20 February 2026 11:43", date)
    forwarded = run_import(carrier(body), extract_forwarded_emails="true")[1]
    assert bool(values(forwarded, "send-date")) == ("+0100" in date)
    assert date in values(forwarded, "header")[0]


def test_subject_cleanup_applies_to_forwarded_message():
    body = PLAIN_FORWARD.replace("Subject: Are", "Subject: Fwd: Re: Are")
    original, forwarded = run_import(carrier(body), extract_forwarded_emails="true", remove_subject_markers="true")
    assert values(original, "subject") == ["suspicious message"]
    assert values(forwarded, "subject") == ["Are you in the office?"]


@pytest.mark.parametrize("body, subtype", [(PLAIN_FORWARD, "plain"), (HTML_FORWARD, "html")])
def test_body_urls_link_to_the_forwarded_object(body, subtype):
    objects = run_import(carrier(body, subtype), extract_forwarded_emails="true", extract_urls="true")
    forwarded = objects[1]
    urls_by_uuid = {o["uuid"]: values(o, "url") for o in objects if o["name"] == "url"}
    assert any(
        urls_by_uuid.get(r["referenced_uuid"]) == ["https://example.org/review"] for r in forwarded["ObjectReference"]
    )


def test_charset_and_non_ascii_headers():
    message = carrier(PLAIN_FORWARD.replace("Name <", "René <").replace("Are you in the office?", "Réunion à midi?"))
    message.set_content(message.get_content(), charset="iso-8859-1")
    forwarded = run_import(message, extract_forwarded_emails="true")[1]
    assert values(forwarded, "from-display-name") == ["René"]
    assert values(forwarded, "subject") == ["Réunion à midi?"]


def test_unknown_charset_does_not_break_extraction():
    message = carrier()
    message.set_param("charset", "unknown-charset")
    # Test the helper directly: PyMISP's carrier parser rejects unknown charsets.
    assert len(email_import.inline_forwarded_messages(message)) == 1


def test_limit_number_of_reconstructed_messages():
    objects = run_import(carrier(PLAIN_FORWARD * (MAX_FORWARDS + 3)), extract_forwarded_emails="true")
    assert len(objects) == MAX_FORWARDS + 1


def test_existing_attachment_processing_is_preserved():
    message = carrier()
    message.add_attachment(b"example data", maintype="application", subtype="octet-stream", filename="sample.txt")
    objects = run_import(message, extract_forwarded_emails="true")
    assert [o["name"] for o in objects] == ["email", "file", "email"]
    assert values(objects[1], "filename") == ["sample.txt"]


def test_config_is_advertised():
    assert "extract_forwarded_emails" in email_import.version()["config"]


@pytest.mark.parametrize(
    "body, subtype",
    [
        (PLAIN_FORWARD.split("\n\nPlease review")[0], "plain"),
        (HTML_FORWARD.replace('<a href="https://example.org/review">Please review</a>', ""), "html"),
    ],
)
def test_header_only_forwards_from_issue(body, subtype):
    assert len(run_import(carrier(body, subtype), extract_forwarded_emails="true")) == 2


def test_multiple_recipients_cc_and_reply_to():
    body = PLAIN_FORWARD.replace(
        "To: Other Name", "To: Person <person@example.org>, Other Name\nCc: cc@example.org\nReply-To: reply@example.org"
    )
    forwarded = run_import(carrier(body), extract_forwarded_emails="true")[1]
    assert values(forwarded, "to") == ["person@example.org"]
    assert values(forwarded, "cc") == ["cc@example.org"]
    assert values(forwarded, "reply-to") == ["reply@example.org"]
    assert "Other Name" in values(forwarded, "to-display-name")


def test_plain_text_body_starts_after_headers():
    forwarded = run_import(carrier(), extract_forwarded_emails="true")[1]
    assert values(forwarded, "email-body") == ["Please review https://example.org/review"]


def test_html_links_without_attribute_values():
    body = HTML_FORWARD.replace("Please review</a>", "Please review</a><a href>Text</a><img src>")
    assert len(run_import(carrier(body, "html"), extract_forwarded_emails="true")) == 2


@pytest.mark.parametrize("body, subtype", [(PLAIN_FORWARD, "plain"), (HTML_FORWARD, "html")])
def test_carrier_and_forward_share_url_object(body, subtype):
    objects = run_import(carrier(body, subtype), extract_forwarded_emails="true", extract_urls="true")
    urls = [obj for obj in objects if obj["name"] == "url"]
    assert len(urls) == 1
    assert values(urls[0], "url") == ["https://example.org/review"]
    for email in (obj for obj in objects if obj["name"] == "email"):
        references = [ref for ref in email["ObjectReference"] if ref["referenced_uuid"] == urls[0]["uuid"]]
        assert len(references) == 1


def test_repeated_urls_across_multiple_forwards():
    body = PLAIN_FORWARD + "\n" + PLAIN_FORWARD
    objects = run_import(carrier(body), extract_forwarded_emails="true", extract_urls="true")
    urls = [obj for obj in objects if obj["name"] == "url"]
    assert len(urls) == 1
    emails = [obj for obj in objects if obj["name"] == "email"]
    assert len(emails) == 3
    for email in emails:
        assert sum(ref["referenced_uuid"] == urls[0]["uuid"] for ref in email["ObjectReference"]) == 1


@pytest.mark.parametrize("indent", [" ", "\t"])
@pytest.mark.parametrize("quote", ["", "> ", "> > "])
def test_folded_forwarded_headers(indent, quote):
    body = (
        "From: Sender <sender@example.org>\n"
        "To: First <first@example.org>,\n"
        f"{indent}Second <second@example.org>\n"
        "Cc: Third <third@example.org>,\n"
        f"{indent}Fourth <fourth@example.org>\n"
        "Subject: A long\n"
        f"{indent}forwarded subject\n\n"
        "Message body.\n"
    )
    body = "\r\n".join(quote + line for line in body.splitlines())
    objects = run_import(carrier(body), extract_forwarded_emails="true")
    assert len(objects) == 2
    forwarded = objects[1]
    assert values(forwarded, "to") == ["first@example.org", "second@example.org"]
    assert values(forwarded, "cc") == ["third@example.org", "fourth@example.org"]
    assert values(forwarded, "subject") == ["A long forwarded subject"]
    assert values(forwarded, "email-body") == ["Message body."]


def test_indented_body_after_blank_line_is_not_a_continuation():
    body = PLAIN_FORWARD.replace("\n\nPlease review", "\n\n    Please review")
    forwarded = run_import(carrier(body), extract_forwarded_emails="true")[1]
    assert values(forwarded, "subject") == ["Are you in the office?"]
    assert values(forwarded, "email-body") == ["Please review https://example.org/review"]


def test_forwarded_subject_cleanup_preserves_upstream_metadata_fix():
    body = PLAIN_FORWARD.replace("Subject: Are", "Subject: [TLP:AMBER] Fwd: Re: Are")
    objects = run_import(carrier(body), extract_forwarded_emails="true", remove_subject_markers="true")
    assert values(objects[1], "subject") == ["[TLP:AMBER] Are you in the office?"]
