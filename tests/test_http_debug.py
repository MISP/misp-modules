import gzip
import io
import logging
from array import array
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from misp_modules import __main__ as server
from misp_modules import http_debug
from misp_modules.modules.expansion import whoisfreaks


@pytest.fixture
def service():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, body, status=200, **headers):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Service", "debug-test")
            for name, value in headers.items():
                self.send_header(name.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/redirect":
                self.respond(b"redirect body", 302, Location="/final")
            elif self.path == "/gzip":
                self.respond(gzip.compress(b"compressed response"), Content_Encoding="gzip")
            elif self.path == "/chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"5\r\nfirst\r\n6\r\nsecond\r\n0\r\n\r\n")
            elif self.path == "/error":
                self.respond(b"service error body", 403)
            elif self.path == "/binary":
                self.respond(b"\x00\xff\x80binary")
            else:
                self.respond(b"full response body")

        def do_POST(self):
            if self.headers.get("Transfer-Encoding") == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline(), 16)
                    if not size:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    self.rfile.read(2)
                body = b"".join(chunks)
            else:
                body = self.rfile.read(int(self.headers["Content-Length"]))
            self.respond(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join()


@pytest.fixture
def tracing(monkeypatch, caplog):
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", requests.adapters.HTTPAdapter.send)
    monkeypatch.setattr(http_debug, "_enabled", False)
    monkeypatch.setattr(server.LOGGER, "propagate", True)
    caplog.set_level(logging.DEBUG, logger="misp-modules")
    http_debug.configure_http_debug(True)
    return caplog


def test_complete_exchange(service, tracing):
    body = "payload-" + "x" * 10000 + "-end"
    with http_debug.module_context("example-module"):
        response = requests.post(service + "/echo?token=secret", data=body, headers={"Authorization": "Bearer secret"})
    assert response.text == body
    assert "module=example-module" in tracing.text
    assert f"POST {service}/echo?token=secret" in tracing.text
    assert "Bearer secret" in tracing.text
    assert "200 OK" in tracing.text
    assert "X-Service" in tracing.text
    assert body in tracing.text
    messages = [record.getMessage() for record in tracing.records if record.name == "misp-modules.http"]
    assert len({message.split()[1] for message in messages}) == 1


def test_redirects_log_each_exchange(service, tracing):
    response = requests.get(service + "/redirect")
    assert response.content == b"full response body"
    assert len(response.history) == 1
    assert "302 Found" in tracing.text
    assert "redirect body" in tracing.text
    assert f"GET {service}/final" in tracing.text
    assert "full response body" in tracing.text


def test_error_response_body(service, tracing):
    response = requests.get(service + "/error")
    assert response.content == b"service error body"
    with pytest.raises(requests.HTTPError):
        response.raise_for_status()
    assert "403 Forbidden" in tracing.text
    assert "service error body" in tracing.text


def test_compressed_response(service, tracing):
    response = requests.get(service + "/gzip")
    assert response.content == b"compressed response"
    assert "compressed response" in tracing.text
    assert "Content-Encoding" in tracing.text


def test_binary_response(service, tracing):
    response = requests.get(service + "/binary")
    assert response.content == b"\x00\xff\x80binary"
    assert repr(response.content) in tracing.text


@pytest.mark.parametrize("path,expected", [("/final", b"full response body"), ("/chunked", b"firstsecond")])
def test_streaming_is_lazy(service, tracing, path, expected):
    with requests.get(service + path, stream=True) as response:
        assert response.raw.tell() == 0
        assert "response body chunk" not in tracing.text
        chunks = list(response.iter_content(chunk_size=3))
        assert b"".join(chunks) == expected
        for chunk in chunks:
            assert repr(chunk) in tracing.text


@pytest.mark.parametrize("method", ["read", "read1", "readinto"])
def test_raw_response_reads(service, tracing, method):
    with requests.get(service + "/final", stream=True) as response:
        if method == "readinto":
            buf = bytearray(4)
            assert response.raw.readinto(buf) == 4
            chunk = bytes(buf)
        else:
            chunk = getattr(response.raw, method)(4)
        assert chunk == b"full"
        assert repr(chunk) in tracing.text


@pytest.mark.parametrize("kind", ["file", "iterator", "buffer-iterator"])
def test_streamed_upload_preserves_body(service, tracing, kind):
    if kind == "file":
        body = io.BytesIO(b"streamed upload")
        body.seek(2)
        expected = b"reamed upload"
    elif kind == "iterator":
        body = iter([b"streamed", b" upload"])
        expected = b"streamed upload"
    else:
        body = iter([memoryview(b"streamed"), memoryview(b" upload")])
        expected = b"streamed upload"
    response = requests.post(service + "/echo", data=body)
    assert response.content == expected
    assert response.request.body is body
    if kind == "file":
        assert not body.closed
        assert body.tell() == len(b"streamed upload")
    assert "request body chunk" in tracing.text
    if kind == "buffer-iterator":
        assert "request body chunk: b'streamed'" in tracing.text
        assert "request body chunk: b' upload'" in tracing.text


@pytest.mark.parametrize("body", [array("B", b"buffer upload"), array("H", [1, 256, 65535])])
def test_buffer_upload_preserves_body(service, tracing, body):
    expected = memoryview(body).tobytes()
    request = requests.Request("POST", service + "/echo", data=body).prepare()
    # requests measures array length in elements, so set the byte length explicitly.
    request.headers["Content-Length"] = str(len(expected))
    with requests.Session() as session:
        response = session.send(request)
    assert response.content == expected
    assert response.request.body is body
    assert f"request body: {expected!r}" in tracing.text


def test_connection_errors_preserved(monkeypatch, caplog):
    error = requests.ConnectionError("service unavailable")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", Mock(side_effect=error))
    monkeypatch.setattr(http_debug, "_enabled", False)
    caplog.set_level(logging.DEBUG, logger="misp-modules")
    http_debug.configure_http_debug(True)
    request = requests.Request("POST", "http://example.invalid", data=b"payload").prepare()
    with pytest.raises(requests.ConnectionError) as caught:
        requests.adapters.HTTPAdapter().send(request)
    assert caught.value is error
    assert request.body == b"payload"
    assert "request failed" in caplog.text


def test_disabled_and_idempotent(service, tracing):
    send = requests.adapters.HTTPAdapter.send
    http_debug.configure_http_debug(True)
    assert requests.adapters.HTTPAdapter.send is send
    http_debug.configure_http_debug(False)
    tracing.clear()
    response = requests.get(service + "/final")
    assert response.content == b"full response body"
    assert not [record for record in tracing.records if record.name == "misp-modules.http"]


def test_concurrent_module_contexts(service, tracing):
    def query(name):
        with http_debug.module_context(name):
            return requests.get(service + "/" + name).content

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(query, ["module-one", "module-two"])) == [b"full response body"] * 2
    for name in ("module-one", "module-two"):
        assert f"module={name} request: GET {service}/{name}" in tracing.text
    assert http_debug._MODULE.get() == "unknown"


@pytest.mark.parametrize("handler_name", ["dict_handler", "handler"])
def test_module_worker_context(service, tracing, monkeypatch, handler_name):
    def handler(**kwargs):
        return {"result": requests.get(service + "/final").text}

    monkeypatch.setattr(server, "MODULES_HANDLERS", {"worker-module": SimpleNamespace(**{handler_name: handler})})
    with ThreadPoolExecutor(max_workers=1) as executor:
        result, outcome = executor.submit(
            server.QueryModule.run_request.__wrapped__, None, "worker-module", b"{}", {}
        ).result()
    assert server.orjson.loads(result) == {"result": "full response body"}
    assert outcome == "successes"
    assert "module=worker-module request" in tracing.text
    assert "module=worker-module response" in tracing.text


@pytest.mark.parametrize(
    "attribute_type,functions",
    [
        ("domain", ["expand_whois", "expand_dns", "get_domain_reputation"]),
        ("ip-src", ["get_ip_whois", "get_geolocation", "get_ip_security"]),
    ],
)
def test_whoisfreaks_nested_worker_context(service, tracing, monkeypatch, attribute_type, functions):
    def lookup(function):
        def query(*args):
            assert requests.get(service + "/" + function).content == b"full response body"
            return ([], None) if function in ("expand_whois", "expand_dns") else (None, None)

        return query

    for function in functions:
        monkeypatch.setattr(whoisfreaks, function, lookup(function))
    monkeypatch.setattr(server, "MODULES_HANDLERS", {"whoisfreaks": whoisfreaks})
    payload = {
        "config": {"apikey": "test-key"},
        "attribute": {"type": attribute_type, "value": "example.org" if attribute_type == "domain" else "192.0.2.1"},
    }
    with ThreadPoolExecutor(max_workers=1) as executor:
        result, outcome = executor.submit(
            server.QueryModule.run_request.__wrapped__, None, "whoisfreaks", server.orjson.dumps(payload), payload
        ).result()
    assert "results" in server.orjson.loads(result)
    assert outcome == "successes"
    for function in functions:
        assert f"module=whoisfreaks request: GET {service}/{function}" in tracing.text
    assert "module=unknown" not in tracing.text
    assert http_debug._MODULE.get() == "unknown"


@pytest.mark.parametrize("debug,extended", [(False, False), (True, False), (False, True)])
def test_logger_option(monkeypatch, debug, extended):
    for name in ("misp-modules", "tornado.access", "py.warnings"):
        logger = logging.getLogger(name)
        for attribute in ("handlers", "level", "propagate"):
            monkeypatch.setattr(logger, attribute, getattr(logger, attribute))
        logger.handlers = []
    configure = Mock()
    monkeypatch.setattr(server, "configure_http_debug", configure)
    server.init_logger(debug=debug, debug_extended=extended)
    assert server.LOGGER.level == (logging.DEBUG if debug or extended else logging.INFO)
    configure.assert_called_once_with(extended)


def test_cli_option(monkeypatch):
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test", "--debug-extended"])
    monkeypatch.setattr(server.signal, "signal", Mock())
    monkeypatch.setattr(server, "warn_if_degraded", Mock())
    monkeypatch.setattr(server.misp_modules, "promote_lib_to_root", Mock())
    monkeypatch.setattr(server.misp_modules, "iterate_modules", Mock(return_value=[]))
    monkeypatch.setattr(server.openapi_builder, "build_document", Mock(return_value={}))
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", Mock())
    monkeypatch.setattr(server, "OPENAPI_DOCUMENT", {})
    init_logger = Mock()
    monkeypatch.setattr(server, "init_logger", init_logger)
    assert server.main() == 0
    init_logger.assert_called_once_with(debug=False, debug_extended=True)
