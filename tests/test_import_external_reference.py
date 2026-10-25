import base64
import json
from unittest.mock import Mock, patch

import pytest

from misp_modules.modules.expansion import import_external_reference as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {}
KIND, VALUE = ("url", "https://example.com/reference")


def query(kind=KIND, value=VALUE, config=None, data=None):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_source(result):
    assert "results" in result, result
    original = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert original["to_ids"] is True
    assert original["comment"] == "source context"
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("value", ["", "  ", 5, []])
def test_invalid_value(value):
    assert "error" in module.handler(query(value=value))


def test_unsupported_type():
    assert "error" in module.handler(query(kind="comment"))


def dns(address="93.184.216.34"):
    return [(2, 1, 6, "", (address, 443))]


def pool_reply(raw=b"<h1>Example</h1><script>ignored()</script>", content_type="text/html", status=200, headers=None):
    reply = Mock(status=status, closed=False, headers={"Content-Type": content_type, **(headers or {})})
    chunks = [raw, b""]
    reply.read1.side_effect = chunks
    return reply


def test_html_capture_pins_dns_and_verifies_hostname():
    pool = Mock()
    pool.urlopen.return_value = pool_reply()
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool) as factory,
    ):
        result = module.handler(query())
    assert_source(result)
    capture = objects(result, "page-capture")[0]
    attachment = next(a for a in capture["Attribute"] if a["object_relation"] == "attachment")
    raw = base64.b64decode(attachment["data"])
    assert b"# Example" in raw
    assert b"ignored" not in raw
    assert factory.call_args.args == ("93.184.216.34", 443)
    assert factory.call_args.kwargs["assert_hostname"] == "example.com"
    assert factory.call_args.kwargs["server_hostname"] == "example.com"
    assert factory.call_args.kwargs["cert_reqs"] == module.ssl.CERT_REQUIRED
    assert pool.urlopen.call_args.kwargs["headers"]["Host"] == "example.com:443"
    pool.close.assert_called_once()


def test_pdf_is_preserved():
    pool = Mock()
    pool.urlopen.return_value = pool_reply(b"%PDF-1.7 test", "application/pdf")
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        result = module.handler(query())
    assert_source(result)
    attribute = next(a for a in objects(result, "page-capture")[0]["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attribute["data"]) == b"%PDF-1.7 test"
    assert attribute["value"] == "reference.pdf"


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1", "224.0.0.1"]
)
def test_private_or_special_address_never_connected(address):
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns(address)),
        patch.object(module.urllib3, "HTTPSConnectionPool") as factory,
    ):
        result = module.handler(query())
    assert "error" in result
    factory.assert_not_called()


def test_mixed_dns_answers_rejected():
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns() + dns("127.0.0.1")),
        patch.object(module.urllib3, "HTTPSConnectionPool") as factory,
    ):
        assert "error" in module.handler(query())
    factory.assert_not_called()


def test_private_redirect_rechecked_and_response_closed():
    pool = Mock()
    reply = pool_reply(status=302, headers={"Location": "https://internal.example"})
    pool.urlopen.return_value = reply
    with (
        patch.object(module.socket, "getaddrinfo", side_effect=[dns(), dns("10.0.0.1")]),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool) as factory,
    ):
        assert "error" in module.handler(query())
    assert factory.call_count == 1
    reply.close.assert_called_once()
    pool.close.assert_called_once()


def test_stream_limit_enforced():
    pool = Mock()
    pool.urlopen.return_value = pool_reply(b"x" * (1024 * 1024 + 1))
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        result = module.handler(query(config={"max_size_mb": 1}))
    assert "exceeds" in result["error"]


@pytest.mark.parametrize(
    "value",
    ["http://user:pass@example.com/", "file:///etc/passwd", "https://example.com:22/", "https://example.com/\\evil"],
)
def test_invalid_url(value):
    assert "error" in module.handler(query(value=value))


def test_invalid_pdf_does_not_become_attachment():
    pool = Mock()
    pool.urlopen.return_value = pool_reply(b"<html>not PDF</html>", "application/pdf")
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        assert "error" in module.handler(query())


def test_encoded_response_rejected_before_decompression():
    pool = Mock()
    reply = pool_reply(b"compressed-data", headers={"Content-Encoding": "gzip"})
    pool.urlopen.return_value = reply
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        result = module.handler(query())
    assert "Encoded references" in result["error"]
    reply.read1.assert_not_called()


def test_slow_stream_obeys_wall_clock_deadline():
    pool = Mock()
    reply = pool_reply()
    pool.urlopen.return_value = reply
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
        patch.object(module.time, "monotonic", side_effect=[100, 100, 101, 131]),
    ):
        result = module.handler(query())
    assert "deadline" in result["error"]
    assert reply.read1.call_count == 1
    reply.connection.sock.settimeout.assert_called_once_with(29)
    reply.close.assert_called_once()


def test_connection_close_socket_remains_bounded():
    pool = Mock()
    reply = pool_reply()
    reply.connection.sock = None
    pool.urlopen.return_value = reply
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        result = module.handler(query())
    assert_source(result)
    assert reply._fp.fp.raw._sock.settimeout.call_count >= 1


def test_completed_response_does_not_reuse_closed_socket():
    pool = Mock()
    reply = pool_reply()
    reply.closed = True
    pool.urlopen.return_value = reply
    with (
        patch.object(module.socket, "getaddrinfo", return_value=dns()),
        patch.object(module.urllib3, "HTTPSConnectionPool", return_value=pool),
    ):
        result = module.handler(query())
    assert_source(result)
    assert reply.read1.call_count == 1
    assert reply.connection.sock.settimeout.call_count == 1
