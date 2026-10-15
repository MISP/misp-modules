"""Read bounded OpenPGP packet metadata; no signature verification is performed.

RFC 9580 sections 4.2, 4.3, 5.2 and 5.5 describe packet framing, criticality,
signature subpackets and fingerprints. Signature values remain opaque bytes.
"""

import base64
import hashlib
from datetime import datetime, timezone

MAX_PACKETS = 20000
MAX_SUBPACKETS = 10000
MAX_METADATA_VALUES = 64
MAX_UID_BYTES = 4096


def _number(data, offset, size):
    if offset + size > len(data):
        raise ValueError("Truncated OpenPGP packet.")
    return int.from_bytes(data[offset : offset + size], "big"), offset + size


def _length(data, offset, subpacket=False):
    first, offset = _number(data, offset, 1)
    if first < 192:
        return first, offset
    if first == 255:
        return _number(data, offset, 4)
    if subpacket or first < 224:
        second, offset = _number(data, offset, 1)
        return ((first - 192) << 8) + second + 192, offset
    # Partial lengths are permitted only for data packets, not key/signature packets.
    raise ValueError("Partial packet lengths are not permitted in public-key certificates.")


def _packets(data):
    offset = 0
    count = 0
    while offset < len(data):
        count += 1
        if count > MAX_PACKETS:
            raise ValueError("The public key exceeds the packet parsing limit.")
        start = offset
        header, offset = _number(data, offset, 1)
        if not header & 0x80:
            raise ValueError("Invalid OpenPGP packet header.")
        if header & 0x40:
            tag = header & 0x3F
            length, offset = _length(data, offset)
        else:
            tag = (header >> 2) & 0x0F
            kind = header & 3
            if kind == 3:
                length = len(data) - offset
            else:
                length, offset = _number(data, offset, 1 << kind)
        end = offset + length
        if end > len(data):
            raise ValueError("Truncated OpenPGP packet body.")
        yield tag, data[offset:end], data[start:end]
        offset = end


def _dearmor(armored):
    lines = armored.strip().splitlines()
    if (
        not lines
        or lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        or lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----"
    ):
        raise ValueError("Expected one ASCII-armored public key.")
    try:
        separator = lines.index("")
    except ValueError as error:
        raise ValueError("Missing OpenPGP armor header separator.") from error
    if any(":" not in line for line in lines[1:separator]):
        raise ValueError("Invalid OpenPGP armor header.")
    payload = lines[separator + 1 : -1]
    if payload and payload[-1].startswith("="):
        # CRC-24 is an optional armor checksum, not signature authentication.
        if len(base64.b64decode(payload.pop()[1:], validate=True)) != 3:
            raise ValueError("Invalid OpenPGP armor checksum encoding.")
    data = base64.b64decode("".join(payload), validate=True)
    if not data:
        raise ValueError("Empty OpenPGP public key.")
    return memoryview(data)


def armor_signature(packet):
    encoded = base64.b64encode(packet).decode("ascii")
    body = "\n".join(encoded[offset : offset + 64] for offset in range(0, len(encoded), 64))
    return f"-----BEGIN PGP SIGNATURE-----\n\n{body}\n-----END PGP SIGNATURE-----"


def _fingerprint(body):
    if len(body) < 6:
        raise ValueError("Truncated public-key packet.")
    if body[0] == 4:
        if len(body) > 65535:
            raise ValueError("Invalid version 4 public-key length.")
        material = b"\x99" + len(body).to_bytes(2, "big") + body.tobytes()
        return hashlib.sha1(material, usedforsecurity=False).hexdigest().upper()
    if body[0] in (5, 6):
        material = bytes([0x95 + body[0]]) + len(body).to_bytes(4, "big") + body.tobytes()
        return hashlib.sha256(material).hexdigest().upper()
    raise ValueError("Unsupported public-key packet version for signature extraction.")


def _subpackets(data):
    offset = 0
    count = 0
    while offset < len(data):
        count += 1
        if count > MAX_SUBPACKETS:
            raise ValueError("The signature exceeds the subpacket parsing limit.")
        length, offset = _length(data, offset, subpacket=True)
        end = offset + length
        if length < 1 or end > len(data):
            raise ValueError("Invalid signature subpacket length.")
        yield data[offset] & 0x7F, data[offset + 1 : end]
        offset = end


def _time(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _metadata(body):
    if not body:
        raise ValueError("Empty signature packet.")
    version = body[0]
    result = {"signature-version": str(version), "issuer-key-id": [], "issuer-fingerprint": [], "creation-time": []}
    if version == 3:
        if len(body) < 20 or body[1] != 5:
            raise ValueError("Invalid version 3 signature packet.")
        result.update(
            {
                "signature-type": f"0x{body[2]:02X}",
                "public-key-algorithm": str(body[15]),
                "hash-algorithm": str(body[16]),
            }
        )
        result["issuer-key-id"].append((body[7:15].hex().upper(), "Version 3 issuer field; unverified."))
        result["creation-time"].append((_time(int.from_bytes(body[3:7], "big")), "Version 3 creation field."))
        return result
    if version not in (4, 6):
        result["warning"] = "Unsupported signature version; the original packet is retained without issuer metadata."
        return result
    if len(body) < 4:
        raise ValueError("Truncated signature header.")
    result.update(
        {
            "signature-type": f"0x{body[1]:02X}",
            "public-key-algorithm": str(body[2]),
            "hash-algorithm": str(body[3]),
        }
    )
    offset = 4
    for hashed in (True, False):
        length, offset = _number(body, offset, 2 if version == 4 else 4)
        end = offset + length
        if end > len(body):
            raise ValueError("Truncated signature subpacket area.")
        location = "Hashed" if hashed else "Unhashed"
        for kind, value in _subpackets(body[offset:end]):
            comment = f"{location} issuer subpacket; unverified."
            if kind == 16:
                if len(value) != 8:
                    raise ValueError("Invalid issuer key ID subpacket.")
                result["issuer-key-id"].append((value.hex().upper(), comment))
            elif kind == 33:
                if not value or value[0] not in (4, 5, 6) or len(value) != (21 if value[0] == 4 else 33):
                    raise ValueError("Invalid issuer fingerprint subpacket.")
                fingerprint = value[1:].hex().upper()
                result["issuer-fingerprint"].append((fingerprint, comment))
                key_id = fingerprint[-16:] if value[0] == 4 else fingerprint[:16]
                result["issuer-key-id"].append(
                    (key_id, f"Derived from {location.lower()} issuer fingerprint; unverified.")
                )
            elif kind == 2 and hashed:
                if len(value) != 4:
                    raise ValueError("Invalid signature creation-time subpacket.")
                result["creation-time"].append((_time(int.from_bytes(value, "big")), "Hashed creation-time subpacket."))
            if (
                sum(len(result[name]) for name in ("issuer-key-id", "issuer-fingerprint", "creation-time"))
                > MAX_METADATA_VALUES
            ):
                raise ValueError("The signature exceeds the metadata claim parsing limit.")
        offset = end
    _, offset = _number(body, offset, 2)  # Leftmost hash bits; not verified.
    if version == 6:
        size, offset = _number(body, offset, 1)
        offset += size
    if offset >= len(body):
        raise ValueError("Missing signature value.")
    return result


def extract_signatures(armored, fingerprint, limit):
    """Return unique top-level signature records and whether the limit was hit.

    Issuer fields, including conflicting hashed/unhashed claims, are preserved.
    A fingerprint match identifies the source certificate, not its authenticity.
    """
    records = []
    seen = set()
    primary = None
    context = {}
    context_kind = "key"
    context_warning = None
    for tag, body, packet in _packets(_dearmor(armored)):
        if tag == 6:
            if primary is not None:
                raise ValueError("Multiple primary keys in the public-key block.")
            primary = _fingerprint(body)
            if primary != fingerprint:
                raise ValueError("The public-key fingerprint does not match the HKP index.")
        elif 40 <= tag <= 63:
            continue  # RFC 9580 section 4.3: ignore unknown non-critical packets without changing the subject.
        elif tag in (10, 12, 21):
            continue  # Marker, local trust and padding do not change the signed subject.
        elif primary is None:
            raise ValueError("A public-key certificate must begin with a primary key.")
        elif tag == 13:
            context = {"uid-sha256": hashlib.sha256(body).hexdigest()}
            context_warning = None
            if len(body) <= MAX_UID_BYTES:
                context["uid"] = body.tobytes().decode("utf-8", errors="replace")
            else:
                context_warning = "UID text exceeds the metadata limit; uid-sha256 identifies the original UID body."
            context_kind = "uid"
        elif tag == 17:
            context = {"user-attribute-sha256": hashlib.sha256(body).hexdigest()}
            context_warning = None
            context_kind = "user-attribute"
        elif tag == 14:
            context = {"subkey-fingerprint": _fingerprint(body)}
            context_warning = None
            context_kind = "subkey"
        elif tag == 2:
            digest = hashlib.sha256(packet).hexdigest()
            record = _metadata(body)
            signature_type = record.get("signature-type")
            subject = {}
            if signature_type in ("0x10", "0x11", "0x12", "0x13", "0x30") and context_kind in ("uid", "user-attribute"):
                subject = context
            elif signature_type in ("0x18", "0x19", "0x28") and context_kind == "subkey":
                subject = context
            identity = (digest, tuple(subject.items()))
            if identity in seen:
                continue
            if len(records) >= limit:
                return records, True
            record.update(subject)
            if subject and context_warning:
                record["warning"] = context_warning
            record.update({"key-fingerprint": primary, "sha256": digest, "signature": armor_signature(packet)})
            records.append(record)
            seen.add(identity)
        else:
            raise ValueError("Unexpected packet in the public-key certificate.")
    if primary is None:
        raise ValueError("Missing primary key in the public-key block.")
    return records, False
