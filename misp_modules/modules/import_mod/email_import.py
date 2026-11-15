#!/usr/bin/env python3
import base64
import json
import re
import zipfile
import zlib
from dataclasses import dataclass
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path

from pymisp.exceptions import MISPObjectException
from pymisp.tools import EMailObject, URLObject, make_binary_objects

from misp_modules.lib.email_forward import inline_forwarded_messages

misperrors = {"error": "Error"}

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.3",
    "author": "Seamus Tuohy, Raphaël Vinot",
    "description": "Email import module for MISP",
    "module-type": ["import"],
    "name": "Email Import",
    "requirements": [],
    "features": (
        "This module can be used to import e-mail text as well as attachments and urls.\nConfiguration parameters are"
        " used to unzip attachments, guess zip attachment passwords, extract urls, remove common subject markers, and"
        " extract partial inline forwarded emails (extract_forwarded_emails, disabled by default): All switches default"
        " to False and accept JSON booleans, 0/1, and case-insensitive yes/no strings. ZIP extraction is limited per"
        " request to 100 members, 50 MiB expanded bytes, and 100 password candidates; each member is limited to 20 MiB."
        " Originals are retained and skipped archives are reported.\nForward extraction supports English"
        " From/To/Cc/Bcc/Reply-To/Sent/Date/Subject header blocks in plain text and HTML, including Outlook. Folded"
        " header values are supported. Each block needs a sender address, a subject, and a recipient or date. At most"
        " 20 partial email objects are linked to the carrier with includes references. Plain text is preferred; HTML is"
        " used if no forwards are found in plain text. Reconstructed attributes have to_ids disabled; the original"
        " email is retained as evidence. Local or unparseable timestamps are preserved as text in the reconstructed"
        " headers. Existing extract_urls and remove_subject_markers settings also apply to forwards. URL objects are"
        " shared between the carrier and forwards that contain the same URL. Submitted EML/MSG bytes are preserved"
        " separately from converted EML and heuristic forwards. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/email_import.md)."
    ),
    "references": ["https://github.com/MISP/mail_to_misp"],
    "input": "E-mail file",
    "output": "MISP Event attributes",
    "logo": "",
}

# unzip_attachments : Unzip all zip files that are not password protected
# guess_zip_attachment_passwords : Try bounded password candidates from common values, subject and body.
# extract_urls : This attempts to extract all URL's from text/html parts of the email
moduleconfig = [
    "unzip_attachments",
    "guess_zip_attachment_passwords",
    "extract_urls",
    "remove_subject_markers",
    "extract_forwarded_emails",
]

MAX_ZIP_MEMBERS = 100
MAX_ZIP_MEMBER_BYTES = 20 * 1024 * 1024
MAX_ZIP_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_ZIP_PASSWORD_ATTEMPTS = 100
MAX_PASSWORD_BYTES = 256
MAX_PASSWORD_TEXT_CHARS = 64 * 1024
ZIP_READ_CHUNK = 64 * 1024


class ZipLimitError(ValueError):
    """An archive exceeded a request-wide extraction budget."""


@dataclass
class ZipBudget:
    members: int = 0
    expanded_bytes: int = 0
    password_attempts: int = 0


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "t", "yes", "y"):
            return True
        if normalized in ("", "0", "false", "f", "no", "n"):
            return False
    raise ValueError(f"{name} must be a boolean, 0/1, or a yes/no string.")


def _add_binary(filename, data, parent, file_objects, comment):
    data.seek(0)
    file_object, main_object, sections = make_binary_objects(pseudofile=data, filename=filename, standalone=False)
    file_object.comment = comment
    file_objects.extend(obj for obj in (file_object, main_object, *sections) if obj)
    parent.add_reference(file_object.uuid, "includes", "Email attachment")
    return file_object


def _attach_original(email_object, data):
    """Never depend on PyMISP's normalized/converted source buffers for evidence."""
    relation = "msg" if email_object.eml_from_msg else "eml"
    email_object.add_attribute(
        relation,
        value=f"Original email.{relation}",
        data=BytesIO(data),
        to_ids=False,
        comment="Original submitted message bytes, unchanged.",
    )
    if email_object.eml_from_msg:
        email_object.add_attribute(
            "eml",
            value="Converted email.eml",
            data=BytesIO(email_object.email.as_bytes()),
            to_ids=False,
            comment="Reconstructed EML converted from MSG; not the original message.",
        )


def dict_handler(request: dict):
    # request data is always base 64 byte encoded
    data = base64.b64decode(request["data"])

    try:
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        options = {name: _boolean(config.get(name), name) for name in moduleconfig}
    except ValueError as exc:
        return {"error": f"Email import configuration: {exc}"}
    unzip = options["unzip_attachments"]
    extract_urls = options["extract_urls"]
    remove_subject_markers = options["remove_subject_markers"]

    # None suppresses PyMISP's source attachment, including on versions where False does not.
    email_object = EMailObject(pseudofile=BytesIO(data), attach_original_email=None, standalone=False)
    _attach_original(email_object, data)
    password_list = get_zip_passwords(email_object.email) if unzip and options["guess_zip_attachment_passwords"] else []
    if remove_subject_markers:
        strip_subject_markers(email_object)

    file_objects = []
    warnings = []
    budget = ZipBudget()
    office_extensions = {
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
    }
    for attachment_name, attachment in email_object.attachments:
        attachment_name = attachment_name or "NameMissing.txt"
        original = _add_binary(
            attachment_name, attachment, email_object, file_objects, "Original email attachment, unchanged."
        )
        if not unzip or Path(attachment_name).suffix[1:].lower() in office_extensions:
            continue
        if not zipfile.is_zipfile(attachment):
            continue
        try:
            unzip_attachment(
                attachment_name, attachment, email_object, file_objects, passwords=password_list, budget=budget
            )
        except (
            ZipLimitError,
            RuntimeError,
            zipfile.BadZipFile,
            NotImplementedError,
            OSError,
            EOFError,
            zlib.error,
        ) as exc:
            warning = f"ZIP attachment {attachment_name!r} was not extracted: {exc}"
            original.comment += " " + warning
            warnings.append(warning)

    url_objects = {}  # Shared by the carrier and all its reconstructed forwards.
    if options["extract_forwarded_emails"]:
        for message in inline_forwarded_messages(email_object.email):
            forwarded = EMailObject(
                pseudofile=BytesIO(message.as_bytes()), attach_original_email=False, standalone=False
            )
            # Some PyMISP versions attach the EML even for False. A reconstruction
            # must not be presented as an original message; the carrier keeps it.
            for attribute in forwarded.get_attributes_by_relation("eml"):
                forwarded.attributes.remove(attribute)
            for name in ("from", "to", "cc", "bcc", "reply-to"):
                for attribute in forwarded.get_attributes_by_relation(name):
                    if "@" not in attribute.value:
                        forwarded.attributes.remove(attribute)
                if name in message:
                    for address in message[name].addresses:
                        if not address.domain and (address.display_name or address.username):
                            forwarded.add_attribute(f"{name}-display-name", address.display_name or address.username)
            for attribute in forwarded.attributes:
                attribute.to_ids = False
            forwarded.comment = "Heuristically reconstructed from an inline forward; headers are unverified claims."
            email_object.add_reference(forwarded.uuid, "includes", "Inline forwarded email (heuristic extraction)")
            if remove_subject_markers:
                strip_subject_markers(forwarded)
            file_objects.append(forwarded)
            if extract_urls:
                add_body_urls(forwarded, file_objects, url_objects)

    if extract_urls:
        add_body_urls(email_object, file_objects, url_objects)

    objects = [email_object.to_dict()]
    if file_objects:
        objects += [o.to_dict() for o in file_objects if o]
    r = {"results": {"Object": objects}}
    if warnings:
        r["warnings"] = warnings
    return r


def add_body_urls(email_object, file_objects, url_objects):
    mail_body = email_object.email.get_body(preferencelist=("html", "plain"))
    if mail_body:
        charset = mail_body.get_content_charset("utf-8")
        if mail_body.get_content_type() == "text/html":
            url_parser = HTMLURLParser()
            url_parser.feed(mail_body.get_payload(decode=True).decode(charset, errors="ignore"))
            urls = url_parser.urls
        else:
            urls = re.findall(
                r"""https?://[^\s<>"']+""",
                mail_body.get_payload(decode=True).decode(charset, errors="ignore"),
            )
        referenced_urls = set()
        for url in urls:
            if not url:
                continue
            url_object = url_objects.get(url)
            if url_object is None:
                try:
                    url_object = URLObject(url, standalone=False)
                except (ValueError, MISPObjectException):
                    continue
                url_objects[url] = url_object
                file_objects.append(url_object)
            if url_object.uuid not in referenced_urls:
                email_object.add_reference(url_object.uuid, "includes", "URL in email body")
                referenced_urls.add(url_object.uuid)


SUBJECT_MARKER_RE = re.compile(
    r"""
    ^\s*
    (?P<prefix>(?:\[[^\]]+\]\s*)*)
    (?:
        (?:re|fw|fwd|wg|aw|sv|tr|rv|vs)
        (?:\[\d+\])?
        \s*:\s*
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def remove_common_subject_markers(subject):
    """Remove leading reply/forward markers while preserving bracketed metadata."""
    cleaned_subject = subject
    while True:
        stripped_subject, substitutions = SUBJECT_MARKER_RE.subn(r"\g<prefix>", cleaned_subject, count=1)
        if not substitutions:
            return cleaned_subject.strip()
        cleaned_subject = stripped_subject


def strip_subject_markers(email_object):
    """Strip common reply/forward markers from the generated email subject attribute."""
    for attribute in email_object.get_attributes_by_relation("subject"):
        stripped_subject = remove_common_subject_markers(attribute.value)
        if stripped_subject:
            attribute.value = stripped_subject


def _zip_members(archive, budget):
    members = archive.infolist()
    if len(members) > MAX_ZIP_MEMBERS - budget.members:
        raise ZipLimitError(f"ZIP member count exceeds the {MAX_ZIP_MEMBERS}-member request limit.")
    budget.members += len(members)
    if any(info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for info in members):
        # ZipExtFile does not bound each decompressor call for BZIP2/LZMA, even with read(size).
        raise NotImplementedError("ZIP extraction supports stored and deflated members only.")
    if any(info.file_size > MAX_ZIP_MEMBER_BYTES for info in members):
        raise ZipLimitError(f"ZIP member exceeds the {MAX_ZIP_MEMBER_BYTES}-byte per-member limit.")
    if sum(info.file_size for info in members) > MAX_ZIP_EXPANDED_BYTES - budget.expanded_bytes:
        raise ZipLimitError(f"Expanded ZIP data exceeds the {MAX_ZIP_EXPANDED_BYTES}-byte request limit.")
    return [info for info in members if not info.is_dir()]


def _read_zip_member(stream, budget):
    output = BytesIO()
    while True:
        remaining = min(MAX_ZIP_MEMBER_BYTES - output.tell(), MAX_ZIP_EXPANDED_BYTES - budget.expanded_bytes)
        if remaining < 0:
            raise ZipLimitError("Expanded ZIP data limit exhausted.")
        size = min(ZIP_READ_CHUNK, remaining + 1)
        # Charge before reading: a failed CRC/decryption read may still have expanded data.
        budget.expanded_bytes += size
        chunk = stream.read(size)
        budget.expanded_bytes -= size - len(chunk)
        if not chunk:
            return output
        if len(chunk) > remaining:
            raise ZipLimitError("Expanded ZIP data exceeds the member or request byte limit.")
        output.write(chunk)


def unzip_attachment(filename, data, email_object, file_objects, password=None, *, passwords=(), budget=None):
    """Extract one ZIP atomically using a budget shared by all attachments and retries.

    Never write archive paths to disk. Directory entries count toward the member
    limit; duplicate names are opened by ZipInfo so each entry is read exactly.
    """
    if budget is None:
        budget = ZipBudget()
    data.seek(0)
    with zipfile.ZipFile(data, "r") as archive:
        members = _zip_members(archive, budget)
        encrypted = any(info.flag_bits & 1 for info in members)
        if encrypted and password is None and not passwords:
            raise RuntimeError("Encrypted ZIP; password guessing is disabled.")
        candidates = [password] if password is not None else passwords if encrypted else [None]
        for candidate in candidates:
            if encrypted:
                if budget.password_attempts >= MAX_ZIP_PASSWORD_ATTEMPTS:
                    raise ZipLimitError(
                        f"ZIP password attempts exceed the {MAX_ZIP_PASSWORD_ATTEMPTS}-attempt request limit."
                    )
                budget.password_attempts += 1
            pwd = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
            extracted = []
            try:
                for info in members:
                    with archive.open(info, mode="r", pwd=pwd) as stream:
                        extracted.append((info.filename, _read_zip_member(stream, budget)))
            except (RuntimeError, zipfile.BadZipFile, zlib.error):
                if not encrypted:
                    raise
                # Failed attempts consume the byte budget and never commit partial objects.
                continue
            comment = f"Extracted from {filename}" + (" (password-protected ZIP)" if encrypted else "")
            for member_name, member_data in extracted:
                _add_binary(member_name, member_data, email_object, file_objects, comment)
            return
    raise RuntimeError("Encrypted ZIP: no candidate password succeeded.")


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
    body = [str(message.get("Subject", ""))[:MAX_PASSWORD_TEXT_CHARS]]
    remaining = MAX_PASSWORD_TEXT_CHARS - len(body[0])
    for part in message.walk():
        if remaining <= 0:
            break
        charset = part.get_content_charset()
        if not charset:
            charset = "utf-8"
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True) or b""
        try:
            text = payload[: remaining * 4].decode(charset, errors="ignore")[:remaining]
        except LookupError:
            text = payload[: remaining * 4].decode("utf-8", errors="ignore")[:remaining]
        remaining -= len(text)
        if part.get_content_type() == "text/plain":
            body.append(text)
        else:
            html_parser = HTMLTextParser()
            html_parser.feed(text)
            body.extend(html_parser.text_data)
    raw_text = "\n".join(body)[:MAX_PASSWORD_TEXT_CHARS].strip()

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
    possible_passwords += individual_words + stripped_words
    # Stable order, bounded candidates and key lengths; do not depend on hash randomization.
    passwords = []
    seen = set()
    for candidate in possible_passwords:
        if not candidate or len(candidate) > MAX_PASSWORD_BYTES:
            continue
        if candidate in seen or len(candidate.encode("utf-8")) > MAX_PASSWORD_BYTES:
            continue
        seen.add(candidate)
        passwords.append(candidate)
        if len(passwords) >= MAX_ZIP_PASSWORD_ATTEMPTS:
            break
    return passwords


class HTMLTextParser(HTMLParser):
    """Parse all text and data from HTML strings."""

    def __init__(self, text_data=None):
        HTMLParser.__init__(self)
        if text_data is None:
            self.text_data = []
        else:
            self.text_data = text_data

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
