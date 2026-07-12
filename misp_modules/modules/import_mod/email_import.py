#!/usr/bin/env python3
import base64
import json
import re
import zipfile
from email import message_from_bytes, policy
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path

from pymisp.tools import EMailObject, URLObject, make_binary_objects

misperrors = {"error": "Error"}

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.2",
    "author": "Seamus Tuohy, Raphaël Vinot",
    "description": "Email import module for MISP",
    "module-type": ["import"],
    "name": "Email Import",
    "requirements": [],
    "features": (
        "This module can be used to import e-mail text as well as attachments and urls.\n3 configuration parameters are"
        " then used to unzip attachments, guess zip attachment passwords, and extract urls: set each one of them to"
        " True or False to process or not the respective corresponding actions."
    ),
    "references": [],
    "input": "E-mail file",
    "output": "MISP Event attributes",
    "logo": "",
}

# unzip_attachments : Unzip all zip files that are not password protected
# guess_zip_attachment_passwords : This attempts to unzip all password protected zip files using all the strings found in the email body and subject
# extract_urls : This attempts to extract all URL's from text/html parts of the email
moduleconfig = ["unzip_attachments", "guess_zip_attachment_passwords", "extract_urls", "extract_forwarded_emails"]


def dict_handler(request: dict):
    # request data is always base 64 byte encoded
    data = base64.b64decode(request["data"])

    email_object = EMailObject(pseudofile=BytesIO(data), attach_original_email=True, standalone=False)

    # Check if we were given a configuration
    config = request.get("config", {})
    # Don't be picky about how the user chooses to say yes to these
    acceptable_config_yes = ["y", "yes", "true", "t"]

    # Do we unzip attachments we find?
    unzip = config.get("unzip_attachments", None)
    if unzip is not None and unzip.lower() in acceptable_config_yes:
        unzip = True

    # Do we try to find passwords for protected zip files?
    zip_pass_crack = config.get("guess_zip_attachment_passwords", None)
    if zip_pass_crack is not None and zip_pass_crack.lower() in acceptable_config_yes:
        zip_pass_crack = True
        password_list = get_zip_passwords(email_object.email)

    # Do we extract URL's from the email.
    extract_urls = config.get("extract_urls", None)
    if extract_urls is not None and extract_urls.lower() in acceptable_config_yes:
        extract_urls = True

    extract_forwarded_emails = config.get("extract_forwarded_emails", "true")
    extract_forwarded_emails = (
        extract_forwarded_emails is True
        or (isinstance(extract_forwarded_emails, str) and extract_forwarded_emails.lower() in acceptable_config_yes)
    )

    file_objects = []  # All possible file objects
    # Get Attachments
    # Get file names of attachments
    for attachment_name, attachment in iter_file_attachments(email_object.email):
        # Create file objects for the attachments
        if not attachment_name:
            attachment_name = "NameMissing.txt"

        temp_filename = Path(attachment_name)
        zipped_files = [
            "doc",
            "docx",
            "dot",
            "dotx",
            "xls",
            "xlsx",
            "xlm",
            "xla",
            "xlc",
            "xlt",
            "xltx",
            "xlw",
            "ppt",
            "pptx",
            "pps",
            "ppsx",
            "pot",
            "potx",
            "potx",
            "sldx",
            "odt",
            "ods",
            "odp",
            "odg",
            "odf",
            "fodt",
            "fods",
            "fodp",
            "fodg",
            "ott",
            "uot",
        ]
        # Attempt to unzip the attachment and return its files
        if unzip and temp_filename.suffix[1:] not in zipped_files:
            try:
                unzip_attachment(attachment_name, attachment, email_object, file_objects)
            except RuntimeError:  # File is encrypted with a password
                if zip_pass_crack is True:
                    password = test_zip_passwords(attachment, password_list)
                    if password:
                        unzip_attachment(
                            attachment_name,
                            attachment,
                            email_object,
                            file_objects,
                            password,
                        )
                    else:  # Inform the analyst that we could not crack password
                        f_object, main_object, sections = make_binary_objects(
                            pseudofile=attachment,
                            filename=attachment_name,
                            standalone=False,
                        )
                        f_object.comment = "Encrypted Zip: Password could not be cracked from message"
                        file_objects.append(f_object)
                        file_objects.append(main_object)
                        file_objects += sections
                        email_object.add_reference(f_object.uuid, "includes", "Email attachment")
            except zipfile.BadZipFile:  # Attachment is not a zipfile
                # Just straight add the file
                f_object, main_object, sections = make_binary_objects(
                    pseudofile=attachment, filename=attachment_name, standalone=False
                )
                file_objects.append(f_object)
                file_objects.append(main_object)
                file_objects += sections
                email_object.add_reference(f_object.uuid, "includes", "Email attachment")
        else:
            # Just straight add the file
            f_object, main_object, sections = make_binary_objects(
                pseudofile=attachment, filename=attachment_name, standalone=False
            )
            file_objects.append(f_object)
            file_objects.append(main_object)
            file_objects += sections
            email_object.add_reference(f_object.uuid, "includes", "Email attachment")

    mail_body = email_object.email.get_body(preferencelist=("html", "plain"))
    if extract_urls and mail_body:
        charset = mail_body.get_content_charset("utf-8")
        if mail_body.get_content_type() == "text/html":
            url_parser = HTMLURLParser()
            url_parser.feed(mail_body.get_payload(decode=True).decode(charset, errors="ignore"))
            urls = url_parser.urls
        else:
            urls = re.findall(
                r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
                mail_body.get_payload(decode=True).decode(charset, errors="ignore"),
            )
        for url in urls:
            if not url:
                continue
            try:
                url_object = URLObject(url, standalone=False)
            except ValueError:
                continue
            file_objects.append(url_object)
            email_object.add_reference(url_object.uuid, "includes", "URL in email body")

    if extract_forwarded_emails:
        file_objects += extract_forwarded_email_objects(email_object)

    objects = [email_object.to_dict()]
    if file_objects:
        objects += [o.to_dict() for o in file_objects if o]
    r = {"results": {"Object": objects}}
    return r


def iter_file_attachments(message):
    """Yield non-email attachments as (filename, BytesIO(content))."""
    for attachment in message.iter_attachments():
        if attachment.get_content_type() == "message/rfc822":
            continue
        content = attachment.get_content()
        if isinstance(content, str):
            content = content.encode()
        yield attachment.get_filename(), BytesIO(content)


def extract_forwarded_email_objects(email_object):
    """Extract attached and inline forwarded emails as dependent email objects."""
    forwarded_objects = []
    seen = set()

    for forwarded_bytes in iter_attached_email_bytes(email_object.email):
        add_forwarded_email_object(email_object, forwarded_objects, seen, forwarded_bytes, "Forwarded email attachment")

    for body in iter_decoded_bodies(email_object.email):
        for forwarded_bytes in find_inline_forwarded_email_bytes(body):
            add_forwarded_email_object(email_object, forwarded_objects, seen, forwarded_bytes, "Inline forwarded email")

    return forwarded_objects


def add_forwarded_email_object(parent_email_object, forwarded_objects, seen, forwarded_bytes, comment):
    digest = forwarded_bytes.strip()
    if not digest or digest in seen:
        return
    try:
        forwarded_object = EMailObject(
            pseudofile=BytesIO(forwarded_bytes), attach_original_email=True, standalone=False
        )
    except Exception:
        return
    seen.add(digest)
    forwarded_object.comment = comment
    parent_email_object.add_reference(forwarded_object.uuid, "includes", comment)
    forwarded_objects.append(forwarded_object)


def iter_attached_email_bytes(message):
    """Yield message/rfc822 attachments as raw bytes."""
    for part in message.walk():
        if part is message or part.get_content_type() != "message/rfc822":
            continue
        payload = part.get_payload()
        if isinstance(payload, list):
            for attached_message in payload:
                yield attached_message.as_bytes(policy=policy.default)
        else:
            decoded = part.get_payload(decode=True)
            if decoded:
                yield decoded


def iter_decoded_bodies(message):
    for part in message.walk():
        if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment":
            continue
        charset = part.get_content_charset("utf-8")
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        text = payload.decode(charset, errors="ignore")
        if part.get_content_type() == "text/html":
            html_parser = HTMLTextParser()
            html_parser.feed(text)
            text = "".join(html_parser.text_data)
        yield text


def find_inline_forwarded_email_bytes(text):
    """Find common forwarded-message blocks and return parseable RFC822 snippets."""
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalised.split("\n")
    for start in find_forwarded_header_starts(lines):
        snippet = build_forwarded_message(lines[start:])
        if snippet:
            yield snippet.encode()


def find_forwarded_header_starts(lines):
    starts = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s*(?:>|&gt;\s*)?(?:From|De|Von)\s*:", line, re.IGNORECASE):
            continue
        window = "\n".join(lines[index:index + 8])
        header_hits = sum(
            1
            for header in ("from", "to", "cc", "sent", "date", "subject")
            if re.search(rf"(?im)^\s*(?:>|&gt;\s*)?{header}\s*:", window)
        )
        if header_hits >= 2:
            starts.append(index)
    return starts


def build_forwarded_message(lines):
    header_lines = []
    body_lines = []
    in_headers = True
    known_headers = {"from", "to", "cc", "bcc", "reply-to", "subject", "date", "sent"}
    for line in lines:
        cleaned = re.sub(r"^\s*(?:>|&gt;)\s?", "", line).strip()
        if in_headers:
            if not cleaned:
                continue
            match = re.match(r"^([A-Za-z-]+)\s*:\s*(.*)$", cleaned)
            if not match:
                if header_lines and not header_lines[-1][1]:
                    header_lines[-1] = (header_lines[-1][0], cleaned)
                elif header_lines:
                    in_headers = False
                    body_lines.append(cleaned)
                continue
            header_name = match.group(1).lower()
            header_value = match.group(2).strip()
            if header_name == "sent":
                header_name = "date"
            if header_name in known_headers:
                header_lines.append((header_name, header_value))
            elif header_lines:
                in_headers = False
                body_lines.append(cleaned)
        else:
            body_lines.append(cleaned)
    if not header_lines or not any(name == "from" for name, _ in header_lines):
        return None
    raw = "\n".join(f"{name.title()}: {value}" for name, value in header_lines)
    raw += "\n\n" + "\n".join(body_lines).strip()
    parsed = message_from_bytes(raw.encode(), policy=policy.default)
    if not parsed.get("From"):
        return None
    return parsed.as_bytes(policy=policy.default).decode()


def unzip_attachment(filename, data, email_object, file_objects, password=None):
    """Extract the contents of a zipfile.

    Args:
        filename (str): A string containing the name of the zip file.
        data (decoded attachment data): Data object decoded from an e-mail part.

    Returns:
        Returns an array containing a dict for each file
        Example Dict {"values":"name_of_file.txt",
                      "data":<Base64 Encoded BytesIO>,
                      "comment":"string here"}

    """
    with zipfile.ZipFile(data, "r") as zf:
        if password is not None:
            comment = f'Extracted from {filename} with password "{password}"'
            password = str.encode(password)  # Byte encoded password required
        else:
            comment = f"Extracted from {filename}"
        for zip_file_name in zf.namelist():  # Get all files in the zip file
            with zf.open(zip_file_name, mode="r", pwd=password) as fp:
                file_data = BytesIO(fp.read())
            f_object, main_object, sections = make_binary_objects(
                pseudofile=file_data, filename=zip_file_name, standalone=False
            )
            f_object.comment = comment
            file_objects.append(f_object)
            file_objects.append(main_object)
            file_objects += sections
            email_object.add_reference(f_object.uuid, "includes", "Email attachment")


def test_zip_passwords(data, test_passwords):
    """Test passwords until one is found to be correct.

    Args:
        data (decoded attachment data): Data object decoded from an e-mail part.
        test_passwords (array): List of strings to test as passwords

    Returns:
        Returns a byte string containing a found password and None if password is not found.

    """
    with zipfile.ZipFile(data, "r") as zf:
        firstfile = zf.namelist()[0]
        for pw_test in test_passwords:
            byte_pwd = str.encode(pw_test)
            try:
                zf.open(firstfile, pwd=byte_pwd)
                return pw_test
            except RuntimeError:  # Incorrect Password
                continue
    return None


def get_zip_passwords(message):
    """Parse message for possible zip password combinations.

    Args:
        message (email.message) Email message object to parse.
    """
    possible_passwords = []
    # Passwords commonly used for malware
    malware_passwords = ["infected", "malware"]
    possible_passwords += malware_passwords
    # Commonly used passwords
    common_passwords = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "abc123",
        "123456789",
        "111111",
        "1234567",
        "iloveyou",
        "adobe123",
        "123123",
        "sunshine",
        "1234567890",
        "letmein",
        "1234",
        "monkey",
        "shadow",
        "sunshine",
        "12345",
        "password1",
        "princess",
        "azerty",
        "trustno1",
        "000000",
    ]

    possible_passwords += common_passwords

    # Not checking for multi-part message because by having an
    # encrypted zip file it must be multi-part.
    body = []
    for part in message.walk():
        charset = part.get_content_charset()
        if not charset:
            charset = "utf-8"
        if part.get_content_type() == "text/plain":
            body.append(part.get_payload(decode=True).decode(charset, errors="ignore"))
        elif part.get_content_type() == "text/html":
            html_parser = HTMLTextParser()
            payload = part.get_payload(decode=True)
            if payload:
                html_parser.feed(payload.decode(charset, errors="ignore"))
                for text in html_parser.text_data:
                    body.append(text)
    raw_text = "\n".join(body).strip()

    # Add subject to text corpus to parse
    if "Subject" in message:
        subject = " " + message.get("Subject")
        raw_text += subject

    # Grab any strings that are marked off by special chars
    marking_chars = [["'", "'"], ['"', '"'], ["[", "]"], ["(", ")"]]
    for char_set in marking_chars:
        regex = re.compile(r"""\{0}([^\{1}]*)\{1}""".format(char_set[0], char_set[1]))
        marked_off = re.findall(regex, raw_text)
        possible_passwords += marked_off

    # Create a list of unique words to test as passwords
    individual_words = re.split(r"\s", raw_text)
    # Also get words with basic punctuation stripped out
    # just in case someone places a password in a proper sentence
    stripped_words = [i.strip(".,;:?!") for i in individual_words]
    unique_words = list(set(individual_words + stripped_words))
    possible_passwords += unique_words

    return possible_passwords


class HTMLTextParser(HTMLParser):
    """Parse all text and data from HTML strings."""

    def __init__(self, text_data=None):
        HTMLParser.__init__(self)
        if text_data is None:
            self.text_data = []
        else:
            self.text_data = text_data

    def handle_starttag(self, tag, attrs):
        if tag in {"br", "div", "p", "hr"}:
            self.text_data.append("\n")

    def handle_endtag(self, tag):
        if tag in {"div", "p"}:
            self.text_data.append("\n")

    def handle_data(self, data):
        self.text_data.append(data)


class HTMLURLParser(HTMLParser):
    """Parse all href targets from HTML strings."""

    def __init__(self, urls=None):
        HTMLParser.__init__(self)
        if urls is None:
            self.urls = []
        else:
            self.urls = urls

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            value = self.urls.append(dict(attrs).get("href"))
        if tag == "img":
            value = self.urls.append(dict(attrs).get("src"))
        else:
            return

        # avoid references like internal cid:
        if value and value.lower().startswith(("http://", "https://")):
            self.urls.append(value)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


if __name__ == "__main__":
    with open("tests/test_no_attach.eml", "r") as email_file:
        dict_handler(json.loads(email_file.read()))
