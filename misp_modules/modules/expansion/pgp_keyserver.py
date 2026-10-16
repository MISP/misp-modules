"""Look up OpenPGP keys and UIDs using an HKP keyserver's machine-readable index."""

import json
import math
import re
from datetime import datetime, timezone
from email.utils import parseaddr
from functools import lru_cache
from importlib import resources
from urllib.parse import unquote, urlencode, urlsplit
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message
from ._pgp_keyserver.signatures import extract_signatures

DEFAULT_KEYSERVER = "https://pgp.circl.lu"
INDEX_LIMIT = 1024 * 1024
KEY_LIMIT = 5 * 1024 * 1024
mispattributes = {
    "input": ["text", "email", "email-src", "email-dst", "target-email", "whois-registrant-email"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.1",
    "author": "MISP Project",
    "description": "Pivot on OpenPGP key IDs, fingerprints, email addresses and UIDs using an HKP keyserver.",
    "module-type": ["expansion", "hover"],
    "name": "PGP Keyserver",
    "logo": "",
    "requirements": [
        "requests",
        "PyMISP",
        "Install the pgp-key and pgp-message object templates in MISP",
        "Install pgp-sign in MISP when extract_signatures is enabled",
    ],
    "features": (
        "Query the machine-readable HKP index, using https://pgp.circl.lu by default. Return one pgp-key object"
        " per result and a pgp-meta object referencing it with extracted-from. Preserve complete UIDs, names,"
        " emails, key IDs, fingerprints, dates and server flags. Fetch ASCII-armored public keys by full"
        " fingerprint only. Search and retrieval are bounded; individual retrieval failures retain index metadata"
        " with an object comment. Keyserver UIDs and flags are unverified claims; signatures and ownership are"
        " not validated. pgp-message is provided for message artifacts linked to pgp-meta; this module does not"
        " retrieve or decrypt messages. Configuration: keyserver, timeout (default 10 seconds per HTTP request),"
        " max_results (default 10, maximum 100). New object templates are bundled for older PyMISP versions."
        " Enable extract_signatures to return pgp-sign objects with the original signature packets, issuer IDs"
        " and fingerprints, signature metadata and UID/subkey context. max_signatures limits signature objects"
        " across the lookup (default 100, maximum 1000). Issuer claims are preserved without verification."
    ),
    "references": ["https://pgp.circl.lu", "https://www.ietf.org/archive/id/draft-shaw-openpgp-hkp-00.html"],
    "input": "A text attribute containing a key ID, fingerprint or UID, or an email attribute.",
    "output": "Linked pgp-key and pgp-meta objects, optional pgp-sign objects, and the original attribute.",
}
moduleconfig = ["keyserver", "timeout", "max_results", "extract_signatures", "max_signatures"]


@lru_cache(maxsize=3)
def _template(name):
    return json.loads(resources.files("misp_modules").joinpath("data", name, "definition.json").read_text())


def _query(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ValueError("A non-empty key ID, fingerprint, email or UID of at most 1024 characters is required.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("The search value must not contain control characters.")
    value = value.strip()
    compact = re.sub(r"\s+", "", value)
    prefixed = compact.lower().startswith("0x")
    identifier = compact[2:] if prefixed else compact
    if re.fullmatch(r"[0-9a-fA-F]+", identifier) and len(identifier) in (8, 16, 40, 64):
        return "0x" + identifier.upper()
    if prefixed:
        raise ValueError("A hexadecimal key ID or fingerprint must contain 8, 16, 40 or 64 digits.")
    return value


def _configuration(config):
    if not isinstance(config, dict):
        raise ValueError("Invalid module configuration.")
    server = config.get("keyserver") or DEFAULT_KEYSERVER
    if not isinstance(server, str) or any(character.isspace() or ord(character) < 32 for character in server):
        raise ValueError("keyserver must be an HTTP(S) base URL.")
    parsed = urlsplit(server)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("keyserver must be an HTTP(S) base URL without credentials, query or fragment.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid keyserver port.")
    timeout = float(config.get("timeout") if config.get("timeout") not in (None, "") else 10)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds.")
    maximum = str(config.get("max_results") if config.get("max_results") not in (None, "") else 10)
    if not maximum.isascii() or not maximum.isdigit() or not 1 <= int(maximum) <= 100:
        raise ValueError("max_results must be an integer between 1 and 100.")
    signatures = config.get("extract_signatures")
    if signatures is None:
        signatures = False
    if isinstance(signatures, (bool, int, str)):
        signatures = str(signatures).strip().lower()
    if signatures not in ("", "false", "0", "no", "off", "true", "1", "yes", "on"):
        raise ValueError("extract_signatures must be a boolean (true/false).")
    signatures = signatures in ("true", "1", "yes", "on")
    signature_limit = config.get("max_signatures")
    signature_limit = str(100 if signature_limit in (None, "") else signature_limit)
    if not signature_limit.isascii() or not signature_limit.isdigit() or not 1 <= int(signature_limit) <= 1000:
        raise ValueError("max_signatures must be an integer between 1 and 1000.")
    return server.rstrip("/") + "/pks/lookup", timeout, int(maximum), signatures, int(signature_limit)


def _get(session, endpoint, params, timeout, limit):
    # Bound the decoded response too: Content-Length alone does not bound gzip data.
    with session.get(endpoint, params=params, timeout=timeout, stream=True) as response:
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("The keyserver response exceeds the size limit; narrow the search.")
        return data.decode("utf-8")


def _timestamp(value):
    if value in ("", "0"):
        return None
    if not value.isascii() or not value.isdigit():
        raise ValueError("Invalid timestamp in the keyserver index.")
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError) as error:
        raise ValueError("Invalid timestamp in the keyserver index.") from error


def _parse_index(text):
    lines = [line for line in text.splitlines() if line]
    if not lines:
        raise ValueError("The keyserver returned an empty HKP index.")
    reported = None
    if lines[0].partition(":")[0] == "info":
        fields = lines.pop(0).split(":")
        if len(fields) > 3:
            raise ValueError("Invalid information record in the keyserver index.")
        fields.extend([""] * (3 - len(fields)))
        # HKP assumes version 1 when the information record or its version is absent.
        if fields[1] not in ("", "1") or (fields[2] and not re.fullmatch(r"[0-9]+", fields[2])):
            raise ValueError("The keyserver did not return a version 1 machine-readable HKP index.")
        if fields[2]:
            reported = int(fields[2])
    keys = {}
    current = None
    for line in lines:
        fields = line.split(":")
        if fields[0] == "pub":
            if len(fields) > 7:
                raise ValueError("Invalid public-key record in the keyserver index.")
            # Empty trailing fields and their separators may be omitted in HKP records.
            fields.extend([""] * (7 - len(fields)))
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})", fields[1]):
                raise ValueError("Invalid public-key record in the keyserver index.")
            identifier = fields[1].upper()
            fingerprint = identifier if len(identifier) in (40, 64) else None
            # v4 key IDs use the low 64 bits; v5/v6 use the high 64 bits.
            key_id = identifier[:16] if len(identifier) == 64 else identifier[-16:]
            if any(value and (not value.isascii() or not value.isdigit()) for value in fields[2:4]):
                raise ValueError("Invalid algorithm or key length in the keyserver index.")
            record = {
                "key-id": key_id,
                "fingerprint": fingerprint,
                "algorithm": fields[2],
                "key-length": fields[3],
                "creation-time": _timestamp(fields[4]),
                "expiration-time": _timestamp(fields[5]),
                "flags": fields[6],
                "uids": {},
            }
            current = keys.setdefault(identifier, record)
        elif fields[0] == "uid":
            if current is None or len(fields) > 5:
                raise ValueError("Invalid UID record in the keyserver index.")
            fields.extend([""] * (5 - len(fields)))
            uid = unquote(fields[1], encoding="utf-8", errors="strict")
            if uid:
                current["uids"].setdefault((uid, fields[4]), None)
        else:
            raise ValueError("Unexpected record in the keyserver index.")
    if reported is None:
        reported = len(keys)
    if reported < len(keys) or (reported and not keys):
        raise ValueError("Incomplete keyserver index.")
    return list(keys.values()), reported


def _public_key(text):
    if text is None:
        raise ValueError("Public key not found.")
    text = text.strip()
    lines = text.splitlines()
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        or lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----"
        or any("-----BEGIN" in line or "-----END" in line for line in lines[1:-1])
    ):
        raise ValueError("The keyserver did not return a single ASCII-armored public key.")
    return text


def _signature_object(record, key_uuid):
    signature = MISPObject("pgp-sign", strict=True, misp_objects_template_custom=_template("pgp-sign"))
    for relation in (
        "signature",
        "sha256",
        "signature-version",
        "signature-type",
        "public-key-algorithm",
        "hash-algorithm",
        "key-fingerprint",
        "subkey-fingerprint",
        "uid",
        "uid-sha256",
        "user-attribute-sha256",
    ):
        if relation in record:
            signature.add_attribute(relation, record[relation], to_ids=False)
    for relation in ("issuer-key-id", "issuer-fingerprint", "creation-time"):
        values = {}
        for value, comment in record[relation]:
            values.setdefault(value, {})[comment] = None
        for value, comments in values.items():
            signature.add_attribute(relation, value, comment=" ".join(comments), to_ids=False)
    signature.comment = "Signature and issuer claims have not been cryptographically verified."
    if record.get("warning"):
        signature.comment += " " + record["warning"]
    signature.add_reference(key_uuid, "extracted-from")
    return signature


def _objects(record, source_uuid, endpoint, session, timeout, signature_limit=None):
    key = MISPObject("pgp-key", strict=True, misp_objects_template_custom=_template("pgp-key"))
    meta = MISPObject("pgp-meta", strict=True)
    signatures = []
    for relation in ("key-id", "fingerprint", "algorithm", "key-length", "creation-time", "expiration-time", "flags"):
        if record[relation]:
            key.add_attribute(relation, record[relation], to_ids=False)
    key.add_attribute("keyserver", endpoint.removesuffix("/pks/lookup"), to_ids=False)
    meta.add_attribute("key-id", record["key-id"], to_ids=False)
    for uid, flags in record["uids"]:
        comment = f"UID: {uid}" + (f"; HKP flags: {flags}" if flags else "")
        key.add_attribute("uid", uid, comment=comment, to_ids=False)
        name, email = parseaddr(uid)
        if email and "@" in email:
            # A UID is not an RFC 5322 address list: a colon in its name is literal.
            if "<" in uid and uid.endswith(">"):
                name = uid.rsplit("<", 1)[0].strip()
            meta.add_attribute("user-id-email", email, comment=comment, to_ids=False)
            if name:
                meta.add_attribute("user-id-name", name, comment=comment, to_ids=False)
        else:
            meta.add_attribute("user-id-name", uid, comment=comment, to_ids=False)

    if record["fingerprint"]:
        params = {"op": "get", "options": "mr", "search": "0x" + record["fingerprint"]}
        key.add_attribute("retrieval-url", endpoint + "?" + urlencode(params), to_ids=False)
        try:
            armored = _public_key(_get(session, endpoint, params, timeout, KEY_LIMIT))
            key.add_attribute("key", armored, to_ids=False)
        except (requests.RequestException, ValueError) as error:
            key.comment = f"Public-key retrieval failed ({type(error).__name__}); HKP index metadata retained."
        else:
            if signature_limit is not None:
                if not signature_limit:
                    key.comment = "Signature extraction skipped: the lookup's max_signatures limit was reached."
                else:
                    try:
                        packets, truncated = extract_signatures(armored, record["fingerprint"], signature_limit)
                        signatures = [_signature_object(packet, key.uuid) for packet in packets]
                        if truncated:
                            key.comment = (
                                "Signature extraction limited by max_signatures; additional packets were omitted."
                            )
                    except ValueError as error:
                        key.comment = f"Signature extraction failed: {error} Public key and HKP metadata retained."
    else:
        key.comment = "No full fingerprint in the HKP index; public-key retrieval skipped to avoid an ambiguous key ID."
    key.add_reference(source_uuid, "related-to")
    meta.add_reference(key.uuid, "extracted-from")
    return key, meta, signatures


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "Invalid request."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported input attribute type."}
    try:
        query = _query(attribute["value"])
        UUID(str(attribute["uuid"]))
        config = request.get("config")
        endpoint, timeout, maximum, signatures_enabled, signature_limit = _configuration(
            {} if config is None else config
        )
        source = MISPAttribute()
        source.from_dict(**attribute)
    except (ValueError, TypeError, PyMISPError) as error:
        return {"error": f"Invalid input or configuration: {error}"}

    event = MISPEvent()
    event.add_attribute(**source)
    try:
        with requests.Session() as session:
            params = {"op": "index", "options": "mr", "fingerprint": "on", "search": query}
            text = _get(session, endpoint, params, timeout, INDEX_LIMIT)
            if text is None:
                return {"error": "No matching public keys found."}
            records, reported = _parse_index(text)
            if not records:
                return {"error": "No matching public keys found."}
            for record in records[:maximum]:
                key, meta, signatures = _objects(
                    record,
                    source.uuid,
                    endpoint,
                    session,
                    timeout,
                    signature_limit if signatures_enabled else None,
                )
                signature_limit -= len(signatures)
                if reported > min(maximum, len(records)):
                    notice = (
                        f"Search limited to {min(maximum, len(records))} of {reported} reported keys; narrow the query."
                    )
                    key.comment = f"{key.comment} {notice}" if key.get("comment") else notice
                event.add_object(key)
                event.add_object(meta)
                for signature in signatures:
                    event.add_object(signature)
    except requests.Timeout:
        return {"error": "The PGP keyserver lookup timed out."}
    except requests.RequestException as error:
        return {"error": f"The PGP keyserver lookup failed ({type(error).__name__})."}
    except (ValueError, PyMISPError) as error:
        return {"error": f"Invalid PGP keyserver response: {error}"}
    result = json.loads(event.to_json())
    return {"results": {name: result[name] for name in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
