import base64
import gzip
import hashlib
import json
import stat
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from pymisp import MISPObject

from misp_modules.lib import web_archive
from misp_modules.modules.import_mod import web_archive_import as module

URI = "https://Example.test/web?x=%2b"
WARC_ID = "urn:uuid:10b97942-d6e1-4db1-89e8-edaf01c25c57"
REVISIT_ID = "urn:uuid:10b97942-d6e1-4db1-89e8-edaf01c25c58"
RESPONSE = (
    b"HTTP/1.1 302 Found\r\n"
    b"Location: /next\r\n"
    b"Content-Type: text/html; charset=UTF-8\r\n"
    b"Content-Length: 12\r\n"
    b"ETag: one\r\n"
    b"ETag: two\r\n"
    b"Cache-Control: private,\r\n"
    b"\tmax-age=0\r\n"
    b"Set-Cookie: PRIVATE_COOKIE\r\n"
    b"\r\nPRIVATE_BODY"
)


def warc(
    block=RESPONSE,
    *,
    kind="response",
    uri=URI,
    id_=WARC_ID,
    version="1.1",
    content_type="application/http; msgtype=response",
    extra=(),
):
    fields = [
        ("WARC-Type", kind),
        ("WARC-Record-ID", f"<{id_}>"),
        ("WARC-Date", "2026-11-21T12:00:00.1234567Z"),
        ("WARC-Target-URI", uri),
        ("Content-Type", content_type),
        ("Content-Length", str(len(block))),
        *extra,
    ]
    header = ("\r\n".join([f"WARC/{version}", *(f"{name}: {value}" for name, value in fields), "", ""])).encode()
    return header + block + b"\r\n\r\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def zip_bytes(entries):
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path, data in entries:
            archive.writestr(path, data)
    return output.getvalue()


def wacz(
    entries,
    *,
    with_hashes=True,
    with_manifest_digest=True,
    legacy=False,
    signature=False,
    resource_override=None,
    digest_override=None,
):
    resources = []
    for path, data in entries:
        entry = {"path": path}
        check = entry
        if legacy:
            entry["hashing"] = "sha256"
            check = entry["stats"] = {}
        check["bytes"] = len(data)
        if with_hashes:
            check["hash"] = sha(data) if legacy else "sha256:" + sha(data)
        resources.append(entry)
    if resource_override:
        resources[0].update(resource_override)
    manifest = json.dumps({"profile": "data-package", "resources": resources}).encode()
    extra = [("datapackage.json", manifest)]
    if with_manifest_digest:
        details = {"path": "datapackage.json", "hash": "sha256:" + sha(manifest)}
        if signature:
            details["signedData"] = {"hash": details["hash"], "signature": "test-fixture"}
        if digest_override:
            details.update(digest_override)
        extra.append(("datapackage-digest.json", json.dumps(details).encode()))
    return zip_bytes(entries + extra)


def result_for(raw, **options):
    return module.handler(json.dumps({"data": base64.b64encode(raw).decode("ascii"), **options}))


def objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {attr["object_relation"]: attr["value"] for attr in obj["Attribute"]}


def check_misp_objects(result):
    refs = {obj["uuid"]: obj for obj in result["results"]["Object"]}
    assert len(refs) == len(result["results"]["Object"])
    for obj in refs.values():
        template = {} if obj["name"] == "file" else {"misp_objects_template_custom": module._template(obj["name"])}
        rebuilt = MISPObject(obj["name"], strict=True, standalone=False, **template)
        rebuilt.from_dict(**obj)
        assert json.loads(rebuilt.to_json(strict=True))["uuid"] == obj["uuid"]
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
        assert all(r["referenced_uuid"] in refs for r in obj.get("ObjectReference", ()))


def test_warc_links_original_capture_and_headers_without_materializing_content():
    req = warc(b"GET /web HTTP/1.1\r\nAuthorization: PRIVATE_REQUEST\r\n\r\n", kind="request")
    response = warc(extra=[("WARC-Payload-Digest", "sha1:DECLARED")])
    raw = req + response
    result = result_for(raw, filename=r"C:\evidence\source.warc")
    (file,) = objects(result, "file")
    (rec,) = objects(result, "warc-record")
    (capture,) = objects(result, "page-capture")
    assert values(file) == {
        "filename": "source.warc",
        "sha256": sha(raw),
        "size-in-bytes": str(len(raw)),
        "mimetype": "application/warc",
    }
    fields = values(rec)
    assert fields["target-uri"] == URI
    assert fields["record-id"] == WARC_ID
    assert fields["record-offset"] == str(len(req))
    assert fields["block-length"] == str(len(RESPONSE))
    assert fields["http-status"] == "302" and fields["http-version"] == "1.1"
    assert fields["declared-payload-digest"] == "sha1:DECLARED"
    assert fields["capture-date"] == "2026-11-21T12:00:00.123456+00:00"
    assert fields["warc-date-raw"] == "2026-11-21T12:00:00.1234567Z"
    headers = [json.loads(a["value"]) for a in rec["Attribute"] if a["object_relation"] == "http-response-header"]
    assert {"name": "content-type", "value": "text/html; charset=UTF-8"} in headers
    assert {"name": "location", "value": "/next"} in headers
    assert {"name": "cache-control", "value": "private, max-age=0"} in headers
    assert [h["value"] for h in headers if h["name"] == "etag"] == ["one", "two"]
    assert "PRIVATE_" not in json.dumps(result)
    assert values(capture) == {"url": URI, "archive-record-id": WARC_ID, "capture-date": fields["capture-date"]}
    assert rec["ObjectReference"][0]["referenced_uuid"] == file["uuid"]
    assert capture["ObjectReference"][0]["referenced_uuid"] == rec["uuid"]
    assert rec["ObjectReference"][0]["relationship_type"] == "extracted-from"
    assert result["summary"]["records_scanned"] == 2 and result["summary"]["captures"] == 1
    assert result == result_for(raw, filename=r"C:\evidence\source.warc")
    check_misp_objects(result)


def test_concatenated_gzip_revisit_and_exact_original_attachment():
    first = warc(version="1.0", uri=f"<{URI}>")
    second = warc(b"", id_=REVISIT_ID, kind="revisit", extra=[("WARC-Refers-To", f"<{WARC_ID}>")])
    non_web = warc(b"sample", uri="urn:example:payload", kind="resource", content_type="text/plain")
    raw = b"".join(gzip.compress(part, mtime=0) for part in (first, second, non_web))
    result = result_for(raw, config={"include_archive": "true"})
    (source,) = objects(result, "file")
    records = objects(result, "warc-record")
    assert len(records) == 2
    assert values(records[0])["warc-version"] == "1.0"
    revisit = values(records[1])
    assert revisit["record-offset"] == str(len(first))
    assert revisit["record-type"] == "revisit"
    assert revisit["refers-to"] == f"<{WARC_ID}>"
    assert "http-status" not in revisit
    attachment = next(a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == raw
    assert result["summary"]["records_scanned"] == 3
    assert result["summary"]["format"] == "warc.gz"
    check_misp_objects(result)


def test_short_fractional_capture_time():
    raw = warc().replace(b"2026-11-21T12:00:00.1234567Z", b"2026-11-21T12:00:00.1Z")
    (record,) = objects(result_for(raw), "warc-record")
    assert values(record)["capture-date"] == "2026-11-21T12:00:00.100000+00:00"


def test_wacz_uses_raw_members_for_hashes_and_reports_signature_scope():
    first = gzip.compress(warc(), mtime=0)
    second = warc(b"sample", kind="resource", content_type="text/plain")
    raw = wacz(
        [("archive/z.warc.gz", first), ("archive/a.warc", second), ("pages/pages.jsonl", b"{}\n")], signature=True
    )
    result = result_for(raw)
    records = objects(result, "warc-record")
    assert [values(r)["member-path"] for r in records] == ["archive/a.warc", "archive/z.warc.gz"]
    assert values(records[0])["record-type"] == "resource"
    assert "http-status" not in values(records[0])
    assert len({r["uuid"] for r in records}) == 2
    integrity = result["summary"]["wacz_integrity"]
    assert integrity == {
        "manifest_digest": "verified",
        "resources_verified": 3,
        "resources_total": 3,
        "signature": "not-verified",
    }
    assert "Only digests" in result["warnings"][0]
    assert json.loads(values(objects(result, "file")[0])["text"]) == integrity
    check_misp_objects(result)


@pytest.mark.parametrize("legacy,with_hashes,count", [(True, True, 1), (False, False, 0)])
def test_wacz_legacy_or_unavailable_digests(legacy, with_hashes, count):
    raw = wacz([("archive/capture.warc", warc())], legacy=legacy, with_hashes=with_hashes, with_manifest_digest=False)
    result = result_for(raw)
    assert len(objects(result, "warc-record")) == 1
    assert result["summary"]["wacz_integrity"]["manifest_digest"] == "not-present"
    assert result["summary"]["wacz_integrity"]["resources_verified"] == count
    assert result["warnings"]


@pytest.mark.parametrize(
    "options,message",
    [
        ({"resource_override": {"hash": "sha256:" + "0" * 64}}, "resource SHA-256"),
        ({"resource_override": {"bytes": 7}}, "resource byte count"),
        ({"resource_override": {"path": "../outside.warc"}}, "relative ZIP path"),
        ({"resource_override": {"path": "https://example.test/capture.warc"}}, "relative ZIP path"),
        ({"resource_override": {"path": "archive/missing.warc"}}, "match the ZIP"),
        ({"resource_override": {"hash": "sha512:" + "0" * 128}}, "declare a SHA-256"),
        ({"digest_override": {"path": "anything.json"}}, "must refer to datapackage"),
        ({"digest_override": {"hash": "sha256:" + "0" * 64}}, "manifest SHA-256"),
        ({"digest_override": {"signedData": {"hash": "0" * 64}}}, "signed metadata SHA-256"),
    ],
)
def test_wacz_rejects_inconsistent_manifest_without_partial_objects(options, message):
    result = result_for(wacz([("archive/a.warc", warc())], **options))
    assert set(result) == {"error"}
    assert message in result["error"]


def test_zip_paths_and_types_are_checked_without_extraction():
    info = ZipInfo("archive/link.warc")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    for data in (
        zip_bytes([(info, b"/target")]),
        zip_bytes([("../archive/outside.warc", warc())]),
        zip_bytes([("archive/a.warc", warc())]),
    ):
        assert set(result_for(data)) == {"error"}


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"WARC/1.1\r\n",
        warc()[:-2],
        warc().replace(b"Content-Length: 12\r\n", b"broken\r\n"),
        warc(extra=[("Content-Length", "12")]),
        warc(uri="https://"),
        warc(id_="not-an-id"),
        warc(block=b"HTTP/1.1 200 OK\r\n"),
        warc(kind="request"),
        gzip.compress(warc())[:-1],
    ],
)
def test_invalid_or_non_capture_records_return_only_error(raw):
    assert set(result_for(raw)) == {"error"}


def test_limits_and_module_metadata(monkeypatch):
    assert module.handler() is False
    assert module.version()["module-type"] == ["import"]
    assert module.introspection()["userConfig"]["include_archive"]["type"] == "Boolean"
    assert set(module.handler('{"data":"!!!"}')) == {"error"}
    assert "include_archive" in result_for(warc(), config={"include_archive": "maybe"})["error"]
    monkeypatch.setattr(web_archive, "MAX_CAPTURES", 1)
    assert "1,000 HTTP(S)" in result_for(warc() + warc())["error"]
    monkeypatch.setattr(web_archive, "MAX_METADATA_BYTES", 1)
    assert "metadata exceeds" in result_for(warc())["error"]
    monkeypatch.setattr(web_archive, "MAX_WARC_BYTES", 40)
    assert "Inflated WARC" in result_for(gzip.compress(warc()))["error"]
