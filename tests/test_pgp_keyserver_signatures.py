import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import pgp_keyserver as pgp
from misp_modules.modules.expansion._pgp_keyserver import signatures
from tests.test_pgp_keyserver import ARMOR, FINGERPRINT, _objects, _request, _response, _run, _values

V6_FINGERPRINT = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
V6_SUBKEY = "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"
V6_ARMOR = Path(__file__).with_name("test_files").joinpath("pgp", "rfc9580-v6-public-key.asc").read_text()
# RFC 9580 Appendix A.1 public-key body and independently published fingerprint.
PUBLIC_BODY = bytes.fromhex(
    "0453f35f0b16092b06010401da470f010107403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406"
)
PUBLIC_FINGERPRINT = "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
ISSUER = "0123456789ABCDEF"
OTHER_ISSUER = "FEDCBA9876543210"


def _armor(data):
    encoded = base64.b64encode(data).decode()
    return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + encoded + "\n-----END PGP PUBLIC KEY BLOCK-----"


def _unarmor(armored):
    payload = armored.split("\n\n", 1)[1].split("-----END", 1)[0].splitlines()
    return base64.b64decode("".join(line for line in payload if not line.startswith("=")), validate=True)


def _packet(kind, body, framing="new"):
    if framing.startswith("old"):
        width = int(framing[3:])
        length_type = {1: 0, 2: 1, 4: 2}[width]
        return bytes([0x80 | (kind << 2) | length_type]) + len(body).to_bytes(width, "big") + body
    if framing == "indeterminate":
        return bytes([0x80 | (kind << 2) | 3]) + body
    if framing == "two":
        length = len(body) - 192
        return bytes([0xC0 | kind, (length >> 8) + 192, length & 255]) + body
    if framing == "five" or len(body) >= 192:
        return bytes([0xC0 | kind, 255]) + len(body).to_bytes(4, "big") + body
    return bytes([0xC0 | kind, len(body)]) + body


def _subpacket(kind, value, width=1):
    data = bytes([kind]) + value
    if width == 5:
        return b"\xff" + len(data).to_bytes(4, "big") + data
    if width == 2:
        length = len(data) - 192
        return bytes([(length >> 8) + 192, length & 255]) + data
    return bytes([len(data)]) + data


def _signature_body(hashed=b"", unhashed=None, kind=0x13, version=4):
    # Synthetic signature values are opaque fixtures; no validity is asserted.
    if unhashed is None:
        unhashed = _subpacket(16, bytes.fromhex(ISSUER))
    width = 4 if version == 6 else 2
    body = bytes([version, kind, 1, 8]) + len(hashed).to_bytes(width, "big") + hashed
    body += len(unhashed).to_bytes(width, "big") + unhashed + b"\x12\x34"
    if version == 6:
        body += b"\x10" + b"s" * 16
    return body + b"\x00\x01\x01"


def _certificate(*packets):
    return _armor(_packet(6, PUBLIC_BODY) + b"".join(packets))


def _lookup(armored, fingerprint=PUBLIC_FINGERPRINT, **config):
    request = _request(extract_signatures=True, **config)
    index = f"info:1:1\npub:{fingerprint}:1:2048:0::\n"
    return _run(request, index=index, downloads=[_response(armored)])


@pytest.mark.parametrize("enabled", [None, False, "", "false", "0", "no", "off", 0])
def test_disabled_extraction_preserves_existing_output_and_does_not_parse(enabled):
    config = {} if enabled is None else {"extract_signatures": enabled}
    with patch.object(pgp, "extract_signatures") as parser:
        result, session = _run(_request(**config))
    parser.assert_not_called()
    assert [obj["name"] for obj in result["results"]["Object"]] == ["pgp-key", "pgp-meta"]
    assert session.get.call_count == 2


@pytest.mark.parametrize("enabled", [True, "true", "1", "yes", "on", " TRUE ", 1])
def test_enabled_extraction_returns_real_signature_packets_and_issuer_pivots(enabled):
    result, session = _run(_request(extract_signatures=enabled))
    key = _objects(result, "pgp-key")[0]
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 3
    assert session.get.call_count == 2  # No issuer lookups or other extra HTTP requests.
    assert {_values(obj, "signature-type")[0] for obj in extracted} == {"0x13", "0x10", "0x18"}
    assert {value for obj in extracted for value in _values(obj, "issuer-key-id")} == {
        "70909C9C006694EB",
        "3A58BA29D10E16A7",
    }
    binding = next(obj for obj in extracted if _values(obj, "signature-type") == ["0x18"])
    assert _values(binding, "subkey-fingerprint") == ["E3D6283DCFC20D1A34232AA4BD8563883959B6A7"]
    for obj in extracted:
        raw = _unarmor(_values(obj, "signature")[0])
        assert _values(obj, "sha256") == [hashlib.sha256(raw).hexdigest()]
        assert raw in _unarmor(ARMOR)
        assert _values(obj, "key-fingerprint") == [FINGERPRINT]
        assert _values(obj, "signature-version") == ["4"]
        assert obj["ObjectReference"][0]["referenced_uuid"] == key["uuid"]
        assert obj["ObjectReference"][0]["relationship_type"] == "extracted-from"
        assert all(attribute["to_ids"] is False for attribute in obj["Attribute"])
        restored = MISPObject("pgp-sign", strict=True, misp_objects_template_custom=pgp._template("pgp-sign"))
        restored.from_dict(**obj)
        restored.to_json()


def test_rfc9580_v6_signatures_derive_issuer_id_from_high_fingerprint_bits():
    result, _ = _lookup(V6_ARMOR, V6_FINGERPRINT)
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 2
    assert [_values(obj, "signature-type") for obj in extracted] == [["0x1F"], ["0x18"]]
    assert _values(extracted[1], "subkey-fingerprint") == [V6_SUBKEY]
    for obj in extracted:
        assert _values(obj, "signature-version") == ["6"]
        assert _values(obj, "issuer-fingerprint") == [V6_FINGERPRINT]
        assert _values(obj, "issuer-key-id") == ["CB186C4F0609A697"]
        assert not _values(obj, "uid")


@pytest.mark.parametrize("framing", ["new", "two", "five", "old1", "old2", "old4", "indeterminate"])
def test_packet_framing_preserves_the_exact_original_signature(framing):
    hashed = _subpacket(20, b"x" * 194, width=2) if framing == "two" else b""
    packet = _packet(2, _signature_body(hashed=hashed), framing)
    result, _ = _lookup(_certificate(_packet(13, b"Example UID"), packet))
    signature = _objects(result, "pgp-sign")[0]
    assert _unarmor(_values(signature, "signature")[0]) == packet
    assert _values(signature, "issuer-key-id") == [ISSUER]
    assert _values(signature, "uid") == ["Example UID"]


@pytest.mark.parametrize("tag", range(40, 64))
def test_unknown_noncritical_packets_anywhere_preserve_signatures_and_subjects(tag):
    extension = _packet(tag, b"opaque extension payload")
    certification = _packet(2, _signature_body())
    binding = _packet(2, _signature_body(kind=0x18))
    direct = _packet(2, _signature_body(kind=0x1F))
    attribute = b"opaque user attribute fixture"
    packets = [
        _packet(6, PUBLIC_BODY),
        direct,
        _packet(13, b"Example UID"),
        certification,
        _packet(14, PUBLIC_BODY),
        binding,
        _packet(17, attribute),
        certification,
    ]
    certificate = _armor(extension + extension.join(packets) + extension)
    result, _ = _lookup(certificate)
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 4
    assert [_unarmor(_values(obj, "signature")[0]) for obj in extracted] == [
        direct,
        certification,
        binding,
        certification,
    ]
    assert not _values(extracted[0], "uid")
    assert _values(extracted[1], "uid") == ["Example UID"]
    assert _values(extracted[2], "subkey-fingerprint") == [PUBLIC_FINGERPRINT]
    assert _values(extracted[3], "user-attribute-sha256") == [hashlib.sha256(attribute).hexdigest()]
    assert all(_values(obj, "issuer-key-id") == [ISSUER] for obj in extracted)
    assert "comment" not in _objects(result, "pgp-key")[0]


@pytest.mark.parametrize("tag", [0, 23, 39])
def test_unknown_critical_packets_still_reject_signature_extraction(tag):
    certificate = _certificate(_packet(2, _signature_body()), _packet(tag, b"unknown critical packet"))
    result, _ = _lookup(certificate)
    assert not _objects(result, "pgp-sign")
    key = _objects(result, "pgp-key")[0]
    assert _values(key, "key") == [certificate]
    assert "Unexpected packet" in key["comment"]
    assert _objects(result, "pgp-meta")


@pytest.mark.parametrize("tag", [40, 63])
@pytest.mark.parametrize("packet_tail", [b"", b"\xff\x00", b"\x05x"])
def test_ignored_noncritical_packets_still_require_valid_framing(tag, packet_tail):
    certificate = _certificate(_packet(2, _signature_body()), bytes([0xC0 | tag]) + packet_tail)
    result, _ = _lookup(certificate)
    assert not _objects(result, "pgp-sign")
    key = _objects(result, "pgp-key")[0]
    assert _values(key, "key") == [certificate]
    assert "Truncated OpenPGP packet" in key["comment"]
    assert _objects(result, "pgp-meta")


@pytest.mark.parametrize("width,size", [(1, 20), (2, 194), (2, 8191), (5, 20)])
def test_signature_subpacket_lengths_do_not_hide_following_issuer_fields(width, size):
    hashed = _subpacket(20, b"x" * size, width=width)
    packet = _packet(2, _signature_body(hashed=hashed))
    result, _ = _lookup(_certificate(packet))
    assert _values(_objects(result, "pgp-sign")[0], "issuer-key-id") == [ISSUER]


def test_v3_signature_issuer_and_creation_fields_are_extracted():
    body = b"\x03\x05\x13" + (1483716566).to_bytes(4, "big") + bytes.fromhex(ISSUER)
    body += b"\x01\x08\x12\x34\x00\x01\x01"
    result, _ = _lookup(_certificate(_packet(13, b"Legacy UID"), _packet(2, body)))
    signature = _objects(result, "pgp-sign")[0]
    assert _values(signature, "signature-version") == ["3"]
    assert _values(signature, "issuer-key-id") == [ISSUER]
    assert _values(signature, "creation-time") == ["2017-01-06T15:29:26+00:00"]


def test_conflicting_issuer_claims_are_preserved_with_their_provenance():
    hashed = _subpacket(33, b"\x04" + bytes.fromhex(PUBLIC_FINGERPRINT))
    unhashed = _subpacket(16, bytes.fromhex(OTHER_ISSUER))
    result, _ = _lookup(_certificate(_packet(2, _signature_body(hashed, unhashed))))
    signature = _objects(result, "pgp-sign")[0]
    assert _values(signature, "issuer-key-id") == [PUBLIC_FINGERPRINT[-16:], OTHER_ISSUER]
    assert _values(signature, "issuer-fingerprint") == [PUBLIC_FINGERPRINT]
    claims = {
        attribute["value"]: attribute["comment"]
        for attribute in signature["Attribute"]
        if attribute["object_relation"] == "issuer-key-id"
    }
    assert "hashed issuer fingerprint" in claims[PUBLIC_FINGERPRINT[-16:]]
    assert "Unhashed" in claims[OTHER_ISSUER]


def test_signature_without_issuer_is_preserved_without_inventing_the_key_owner_as_issuer():
    result, _ = _lookup(_certificate(_packet(2, _signature_body(unhashed=b""))))
    signature = _objects(result, "pgp-sign")[0]
    assert _values(signature, "signature")
    assert not _values(signature, "issuer-key-id")
    assert not _values(signature, "issuer-fingerprint")


def test_unsupported_signature_version_preserves_the_original_packet():
    packet = _packet(2, b"\x05opaque-signature")
    result, _ = _lookup(_certificate(packet))
    signature = _objects(result, "pgp-sign")[0]
    assert _values(signature, "signature-version") == ["5"]
    assert not _values(signature, "issuer-key-id")
    assert _unarmor(_values(signature, "signature")[0]) == packet
    assert "Unsupported signature version" in signature["comment"]


def test_embedded_signatures_are_preserved_in_the_parent_packet_without_extra_objects():
    embedded = _signature_body(unhashed=_subpacket(16, bytes.fromhex(OTHER_ISSUER)))
    packet = _packet(2, _signature_body(hashed=_subpacket(32, embedded)))
    result, _ = _lookup(_certificate(packet))
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 1
    assert _values(extracted[0], "issuer-key-id") == [ISSUER]
    assert embedded in _unarmor(_values(extracted[0], "signature")[0])


def test_duplicate_signature_packets_are_deduplicated_per_signed_subject():
    packet = _packet(2, _signature_body())
    certificate = _certificate(_packet(13, b"First UID"), packet, packet, _packet(13, b"Second UID"), packet)
    result, _ = _lookup(certificate)
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 2
    assert [_values(obj, "uid") for obj in extracted] == [["First UID"], ["Second UID"]]


def test_direct_key_signatures_do_not_inherit_uid_context():
    packet = _packet(2, _signature_body(kind=0x1F))
    result, _ = _lookup(_certificate(_packet(13, b"First UID"), packet, _packet(13, b"Second UID"), packet))
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 1
    assert not _values(extracted[0], "uid")


def test_user_attribute_context_uses_its_exact_body_hash():
    attribute = b"opaque user attribute fixture"
    result, _ = _lookup(_certificate(_packet(17, attribute), _packet(2, _signature_body())))
    signature = _objects(result, "pgp-sign")[0]
    assert _values(signature, "user-attribute-sha256") == [hashlib.sha256(attribute).hexdigest()]


def test_large_uids_are_identified_by_hash_without_repeating_their_full_text_in_every_signature():
    uid = b"x" * (signatures.MAX_UID_BYTES + 1)
    result, _ = _lookup(_certificate(_packet(13, uid), _packet(2, _signature_body())))
    signature = _objects(result, "pgp-sign")[0]
    assert not _values(signature, "uid")
    assert _values(signature, "uid-sha256") == [hashlib.sha256(uid).hexdigest()]
    assert "UID text exceeds" in signature["comment"]


def test_non_utf8_uid_bodies_remain_distinct_even_when_their_display_text_matches():
    packet = _packet(2, _signature_body())
    result, _ = _lookup(_certificate(_packet(13, b"\xff"), packet, _packet(13, b"\xfe"), packet))
    extracted = _objects(result, "pgp-sign")
    assert len(extracted) == 2
    assert _values(extracted[0], "uid-sha256") != _values(extracted[1], "uid-sha256")


def test_excessive_issuer_claims_do_not_expand_into_an_unbounded_number_of_attributes():
    claims = b"".join(_subpacket(16, number.to_bytes(8, "big")) for number in range(signatures.MAX_METADATA_VALUES + 1))
    result, _ = _lookup(_certificate(_packet(2, _signature_body(unhashed=claims))))
    assert not _objects(result, "pgp-sign")
    assert "metadata claim parsing limit" in _objects(result, "pgp-key")[0]["comment"]


def test_max_signatures_is_a_global_limit_and_keeps_all_lookup_keys():
    index = f"info:1:2\npub:{FINGERPRINT}:1:2048:0::\npub:{V6_FINGERPRINT}:27:256:0::\n"
    result, session = _run(
        _request(extract_signatures=True, max_signatures=1), index, [_response(ARMOR), _response(V6_ARMOR)]
    )
    assert len(_objects(result, "pgp-sign")) == 1
    keys = _objects(result, "pgp-key")
    assert len(keys) == 2
    assert all(_values(key, "key") for key in keys)
    assert all("max_signatures" in key["comment"] for key in keys)
    assert session.get.call_count == 3


def test_certificate_without_signatures_returns_key_metadata_without_a_failure_comment():
    result, _ = _lookup(_certificate())
    assert not _objects(result, "pgp-sign")
    assert "comment" not in _objects(result, "pgp-key")[0]


@pytest.mark.parametrize(
    "packet",
    [
        b"\x00",
        b"\xc2",
        b"\xc2\xff\x00",
        b"\xc2\xe0",
        b"\xc2\x05x",
        _packet(2, b""),
        _packet(2, b"\x04"),
        _packet(2, b"\x04\x13\x01\x08\xff\xff"),
        _packet(2, _signature_body(hashed=b"\x00")),
        _packet(2, _signature_body(hashed=b"\x05\x10x")),
        _packet(2, _signature_body(hashed=_subpacket(16, b"short"))),
        _packet(2, _signature_body(hashed=_subpacket(33, b"\x04short"))),
        _packet(2, _signature_body(hashed=_subpacket(2, b"short"))),
        _packet(2, _signature_body(version=6)[:-20]),
        _packet(6, PUBLIC_BODY),
        _packet(5, b"unexpected secret-key packet"),
    ],
)
def test_malformed_packets_keep_the_public_key_and_index_metadata(packet):
    result, _ = _lookup(_certificate(packet))
    assert not _objects(result, "pgp-sign")
    key = _objects(result, "pgp-key")[0]
    assert _values(key, "key")
    assert "Signature extraction failed" in key["comment"]
    assert _values(_objects(result, "pgp-meta")[0], "key-id") == [PUBLIC_FINGERPRINT[-16:]]


def test_fingerprint_mismatch_keeps_metadata_without_attaching_signatures_to_the_wrong_key():
    result, _ = _lookup(ARMOR)
    assert not _objects(result, "pgp-sign")
    assert "fingerprint does not match" in _objects(result, "pgp-key")[0]["comment"]


@pytest.mark.parametrize("constant", ["MAX_PACKETS", "MAX_SUBPACKETS"])
def test_packet_parsing_limits_fail_without_discarding_the_key(constant, monkeypatch):
    monkeypatch.setattr(signatures, constant, 1)
    result, _ = _run(_request(extract_signatures=True))
    assert not _objects(result, "pgp-sign")
    key = _objects(result, "pgp-key")[0]
    assert _values(key, "key")
    assert "parsing limit" in key["comment"]


@pytest.mark.parametrize(
    "config",
    [
        {"extract_signatures": "maybe"},
        {"extract_signatures": []},
        {"extract_signatures": {}},
        {"extract_signatures": 2},
        {"max_signatures": 0},
        {"max_signatures": 1001},
        {"max_signatures": True},
        {"max_signatures": "1.5"},
    ],
)
def test_invalid_signature_configuration_is_rejected_before_network(config):
    with patch.object(pgp.requests, "Session") as session:
        result = pgp.handler(json.dumps(_request(**config)))
    assert "error" in result
    session.assert_not_called()
