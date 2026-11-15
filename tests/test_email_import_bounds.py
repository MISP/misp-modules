"""Configuration, bounded ZIP extraction and original-message evidence."""

import base64
import zipfile
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path

import pytest

from misp_modules.modules.import_mod import email_import

FORWARD = """From: sender@example.org
To: analyst@example.net
Subject: Re: forwarded

Review https://example.org/path
"""


def _zip(entries, compression=zipfile.ZIP_DEFLATED):
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return output.getvalue()


def _message(attachments=(), body=FORWARD):
    message = EmailMessage()
    message["From"] = "reporter@example.org"
    message["To"] = "soc@example.net"
    message["Subject"] = "Fwd: carrier"
    message.set_content(body)
    for name, data in attachments:
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return message


def _import(message, config=None):
    raw = message.as_bytes() if isinstance(message, EmailMessage) else message
    return email_import.dict_handler({"data": base64.b64encode(raw), "config": config})


def _objects(result, kind):
    return [obj for obj in result["results"]["Object"] if obj["name"] == kind]


def _attributes(obj, relation):
    return [attribute for attribute in obj["Attribute"] if attribute["object_relation"] == relation]


def _filenames(result):
    return [attribute["value"] for obj in _objects(result, "file") for attribute in _attributes(obj, "filename")]


@pytest.mark.parametrize(
    "value,enabled",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("false", False),
        ("TRUE", True),
        (" FALSE ", False),
        ("yes", True),
        ("no", False),
        ("y", True),
        ("n", False),
        ("t", True),
        ("f", False),
        ("1", True),
        ("0", False),
        ("", False),
        (None, False),
    ],
)
def test_all_switches_use_normalized_booleans(value, enabled):
    message = _message([("archive.zip", _zip([("child.txt", b"child")]))])
    result = _import(message, {name: value for name in email_import.moduleconfig})
    assert ("child.txt" in _filenames(result)) is enabled
    assert bool(_objects(result, "url")) is enabled
    assert len(_objects(result, "email")) == (2 if enabled else 1)
    subject = _attributes(_objects(result, "email")[0], "subject")[0]["value"]
    assert subject == ("carrier" if enabled else "Fwd: carrier")


@pytest.mark.parametrize("name", email_import.moduleconfig)
@pytest.mark.parametrize("value", ["sometimes", [], {}, 2, 1.0])
def test_invalid_switch_values_are_rejected(name, value):
    result = _import(_message(), {name: value})
    assert name in result["error"]
    assert "results" not in result


@pytest.mark.parametrize("config", [[], "", True])
def test_invalid_config_is_rejected(config):
    result = _import(_message(), config)
    assert "config" in result["error"]
    assert "results" not in result


def test_default_configuration_keeps_zip_intact():
    result = _import(_message([("archive.zip", _zip([("child.txt", b"data")]))]))
    assert _filenames(result) == ["archive.zip"]
    assert not _objects(result, "url")


@pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"])
def test_original_eml_bytes_survive_subject_cleanup_and_forward_extraction(bom):
    raw = bom + _message().as_bytes().replace(b"\n", b"\r\n") + b"\r\n \t"
    result = _import(raw, {"remove_subject_markers": True, "extract_forwarded_emails": True})
    carrier, forwarded = _objects(result, "email")
    source = _attributes(carrier, "eml")
    assert len(source) == 1
    assert source[0]["data"].getvalue() == raw
    assert source[0]["to_ids"] is False
    assert "unchanged" in source[0]["comment"]
    assert not _attributes(forwarded, "eml")
    assert not _attributes(forwarded, "msg")
    assert all(attribute["to_ids"] is False for attribute in forwarded["Attribute"])


def test_original_msg_is_separate_from_converted_eml(monkeypatch):
    raw = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1original MSG bytes\r\n \t"
    converted = _message()
    monkeypatch.setattr(email_import.EMailObject, "_msg_to_eml", lambda self, data: converted)
    result = _import(raw, {"remove_subject_markers": True})
    carrier = _objects(result, "email")[0]
    original = _attributes(carrier, "msg")
    reconstructed = _attributes(carrier, "eml")
    assert len(original) == len(reconstructed) == 1
    assert original[0]["data"].getvalue() == raw
    assert reconstructed[0]["data"].getvalue() == converted.as_bytes()
    assert "not the original" in reconstructed[0]["comment"]
    assert original[0]["to_ids"] is reconstructed[0]["to_ids"] is False


def test_original_archive_and_duplicate_members_are_preserved():
    raw = _zip([("same.txt", b"first"), ("same.txt", b"second"), ("directory/", b"")])
    result = _import(_message([("archive.zip", raw)]), {"unzip_attachments": True})
    assert _filenames(result) == ["archive.zip", "same.txt", "same.txt"]
    payloads = [_attributes(obj, "malware-sample")[0]["data"].getvalue() for obj in _objects(result, "file")]
    assert payloads == [raw, b"first", b"second"]


@pytest.mark.parametrize("filename", ["archive.DOCX", "archive.odt"])
def test_office_containers_are_not_unpacked(filename):
    result = _import(_message([(filename, _zip([("inside", b"data")]))]), {"unzip_attachments": True})
    assert _filenames(result) == [filename]


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_compression_with_unbounded_zipfile_decompressor_is_preserved_without_extraction(compression):
    result = _import(_message([("archive.zip", _zip([("child", b"data")], compression))]), {"unzip_attachments": True})
    assert _filenames(result) == ["archive.zip"]
    assert "stored and deflated" in result["warnings"][0]


def test_member_limit_is_shared_between_attachments(monkeypatch):
    monkeypatch.setattr(email_import, "MAX_ZIP_MEMBERS", 2)
    first = _zip([("first", b"1")])
    second = _zip([("second", b"2"), ("third", b"3")])
    result = _import(_message([("one.zip", first), ("two.zip", second)]), {"unzip_attachments": True})
    assert _filenames(result) == ["one.zip", "first", "two.zip"]
    assert "member" in result["warnings"][0]


def test_directories_also_consume_member_budget(monkeypatch):
    monkeypatch.setattr(email_import, "MAX_ZIP_MEMBERS", 1)
    result = _import(_message([("archive.zip", _zip([("a/", b""), ("b/", b"")]))]), {"unzip_attachments": True})
    assert _filenames(result) == ["archive.zip"]
    assert "member" in result["warnings"][0]


@pytest.mark.parametrize("limit,value", [("MAX_ZIP_MEMBER_BYTES", 4), ("MAX_ZIP_EXPANDED_BYTES", 4)])
def test_declared_oversized_members_are_rejected_before_read(monkeypatch, limit, value):
    monkeypatch.setattr(email_import, limit, value)

    def forbidden_read(*args, **kwargs):
        pytest.fail("An oversized archive member was read")

    monkeypatch.setattr(zipfile.ZipExtFile, "read", forbidden_read)
    result = _import(_message([("archive.zip", _zip([("bomb", b"x" * 100000)]))]), {"unzip_attachments": True})
    assert _filenames(result) == ["archive.zip"]
    assert "limit" in result["warnings"][0]


def test_expanded_bytes_are_shared_across_attachments(monkeypatch):
    monkeypatch.setattr(email_import, "MAX_ZIP_EXPANDED_BYTES", 7)
    attachments = [(f"{index}.zip", _zip([(f"child{index}", b"1234")])) for index in range(2)]
    result = _import(_message(attachments), {"unzip_attachments": True})
    assert _filenames(result) == ["0.zip", "child0", "1.zip"]
    assert "request limit" in result["warnings"][0]


def test_stream_reads_are_bounded_even_if_declared_size_is_wrong(monkeypatch):
    monkeypatch.setattr(email_import, "MAX_ZIP_EXPANDED_BYTES", 10)
    monkeypatch.setattr(email_import, "ZIP_READ_CHUNK", 4)

    class Stream(BytesIO):
        def read(self, size=-1):
            assert 0 < size <= 4
            return super().read(size)

    stream = Stream(b"x" * 100)
    budget = email_import.ZipBudget()
    with pytest.raises(email_import.ZipLimitError):
        email_import._read_zip_member(stream, budget)
    assert stream.tell() == budget.expanded_bytes == 11  # One lookahead byte detects the overflow.


def test_failed_reads_still_consume_byte_budget(monkeypatch):
    monkeypatch.setattr(email_import, "ZIP_READ_CHUNK", 4)

    class CorruptStream:
        def read(self, size):
            raise zipfile.BadZipFile("CRC failure after decompression")

    budget = email_import.ZipBudget()
    with pytest.raises(zipfile.BadZipFile):
        email_import._read_zip_member(CorruptStream(), budget)
    assert budget.expanded_bytes == 4


def test_corrupt_archive_does_not_commit_partial_extraction():
    raw = _zip([("good.txt", b"good"), ("failed.txt", b"content-to-corrupt")], zipfile.ZIP_STORED)
    raw = raw.replace(b"content-to-corrupt", b"Content-to-corrupt", 1)
    result = _import(_message([("archive.zip", raw)]), {"unzip_attachments": True})
    assert _filenames(result) == ["archive.zip"]
    assert "CRC" in result["warnings"][0]


@pytest.mark.parametrize("fixture", ["infected.zip", "short_password.zip", "longer_password.zip"])
def test_real_encrypted_archives(fixture):
    raw = (Path(__file__).parent / fixture).read_bytes()
    result = _import(
        _message([("encrypted.zip", raw)], body='Use "a long password" or STRINGS.'),
        {
            "unzip_attachments": True,
            "guess_zip_attachment_passwords": True,
        },
    )
    assert _filenames(result) == ["encrypted.zip", "EICAR.com"]
    assert not result.get("warnings")


@pytest.mark.parametrize("guess", [False, "false", "no", 0])
def test_password_guessing_can_be_disabled(guess):
    raw = (Path(__file__).parent / "infected.zip").read_bytes()
    result = _import(
        _message([("encrypted.zip", raw)]),
        {
            "unzip_attachments": True,
            "guess_zip_attachment_passwords": guess,
        },
    )
    assert _filenames(result) == ["encrypted.zip"]
    assert "disabled" in result["warnings"][0]


def test_password_attempt_limit_is_shared_by_attachments(monkeypatch):
    monkeypatch.setattr(email_import, "MAX_ZIP_PASSWORD_ATTEMPTS", 2)
    raw = (Path(__file__).parent / "infected.zip").read_bytes()
    result = _import(
        _message([(f"{index}.zip", raw) for index in range(3)]),
        {
            "unzip_attachments": True,
            "guess_zip_attachment_passwords": True,
        },
    )
    assert _filenames(result) == ["0.zip", "EICAR.com", "1.zip", "EICAR.com", "2.zip"]
    assert "attempt" in result["warnings"][0]


def test_mixed_archive_checks_encrypted_member_and_discards_wrong_attempt_output():
    raw = BytesIO((Path(__file__).parent / "infected.zip").read_bytes())
    with zipfile.ZipFile(raw, "a") as archive:
        archive.writestr("plain.txt", b"prefix")
        archive.filelist.reverse()  # Put the unencrypted member first in the central directory.
    budget = email_import.ZipBudget()
    parent = email_import.EMailObject(pseudofile=BytesIO(_message().as_bytes()), attach_original_email=None)
    objects = []
    email_import.unzip_attachment("mixed.zip", raw, parent, objects, passwords=["wrong", "infected"], budget=budget)
    filenames = [attribute.value for obj in objects for attribute in obj.get_attributes_by_relation("filename")]
    assert filenames == ["plain.txt", "EICAR.com"]
    assert budget.password_attempts == 2
    assert budget.expanded_bytes >= 2 * len(b"prefix")


def test_password_candidates_are_bounded_and_deterministic():
    message = _message(body='"a long password" ' + " ".join(f"candidate{index}" for index in range(1000)))
    candidates = email_import.get_zip_passwords(message)
    assert candidates == email_import.get_zip_passwords(message)
    assert len(candidates) == len(set(candidates)) == email_import.MAX_ZIP_PASSWORD_ATTEMPTS
    assert candidates[:2] == ["infected", "malware"]
    assert "a long password" in candidates
    assert all(0 < len(candidate.encode("utf-8")) <= email_import.MAX_PASSWORD_BYTES for candidate in candidates)


def test_failed_password_trials_cannot_reset_expansion_budget(monkeypatch):
    raw = BytesIO((Path(__file__).parent / "infected.zip").read_bytes())
    with zipfile.ZipFile(raw, "a") as archive:
        archive.writestr("plain.txt", b"x" * 128)
        archive.filelist.reverse()
    # Enough for a complete attempt, but not for two plaintext prefixes.
    monkeypatch.setattr(email_import, "MAX_ZIP_EXPANDED_BYTES", 200)
    budget = email_import.ZipBudget()
    parent = email_import.EMailObject(pseudofile=BytesIO(_message().as_bytes()), attach_original_email=None)
    objects = []
    with pytest.raises(email_import.ZipLimitError):
        email_import.unzip_attachment("mixed.zip", raw, parent, objects, passwords=["wrong", "infected"], budget=budget)
    assert not objects
    assert budget.expanded_bytes == 201
    assert budget.password_attempts == 2
