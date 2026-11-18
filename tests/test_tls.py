import asyncio
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
import tornado.httpclient
import tornado.httpserver
import tornado.netutil
import tornado.web

from misp_modules import __main__ as server
from misp_modules import openapi, tls


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl is needed to generate a test certificate")
    folder = tmp_path_factory.mktemp("tls")
    certfile, keyfile = folder / "cert.pem", folder / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(keyfile),
            "-out",
            str(certfile),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return certfile, keyfile


@pytest.fixture
def startup(monkeypatch):
    for name in ("init_logger", "warn_if_degraded"):
        monkeypatch.setattr(server, name, Mock())
    monkeypatch.setattr(server.signal, "signal", Mock())
    monkeypatch.setattr(server.misp_modules, "promote_lib_to_root", Mock())
    monkeypatch.setattr(server.misp_modules, "iterate_modules", Mock(return_value=[]))
    monkeypatch.setattr(server, "MODULES_HANDLERS", {})
    monkeypatch.setattr(server, "OPENAPI_DOCUMENT", {})
    httpserver = Mock()
    monkeypatch.setattr(server.tornado.httpserver, "HTTPServer", httpserver)
    return httpserver


def test_plain_http_remains_default(monkeypatch, startup):
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test"])
    assert server.main() == 0
    assert startup.call_args.kwargs["ssl_options"] is None
    assert server.OPENAPI_DOCUMENT["servers"] == [{"url": "http://localhost:6666"}]


def test_tls_startup_uses_context_and_https(monkeypatch, startup, certificate):
    certfile, keyfile = certificate
    monkeypatch.setattr(
        "sys.argv", ["misp-modules", "--test", "--tls-certfile", str(certfile), "--tls-keyfile", str(keyfile)]
    )
    assert server.main() == 0
    context = startup.call_args.kwargs["ssl_options"]
    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert server.OPENAPI_DOCUMENT["servers"] == [{"url": "https://localhost:6666"}]


@pytest.mark.parametrize(
    "options",
    [
        ["--tls-certfile", "missing.pem"],
        ["--tls-keyfile", "missing.pem"],
        ["--tls-certfile", "missing.pem", "--tls-keyfile", "missing.key"],
        ["--tls-certfile", ""],
        ["--tls-certfile", "", "--tls-keyfile", ""],
    ],
)
def test_invalid_tls_stops_before_listening(monkeypatch, startup, capsys, options):
    monkeypatch.setattr("sys.argv", ["misp-modules", "--test", *options])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 2
    startup.assert_not_called()
    assert "Unable to configure API TLS" in capsys.readouterr().err


def test_invalid_certificate_is_not_a_plaintext_fallback(tmp_path):
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("invalid certificate")
    with pytest.raises(ssl.SSLError):
        tls.server_context(invalid, invalid)


def test_mismatched_key_is_rejected(certificate, tmp_path):
    certfile, _ = certificate
    other_key = tmp_path / "other.key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other_key)],
        check=True,
        capture_output=True,
        timeout=15,
    )
    with pytest.raises(ssl.SSLError):
        tls.server_context(certfile, other_key)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_openapi_ipv6_url(scheme):
    assert openapi.build_document({}, "::1", 6666, scheme=scheme)["servers"] == [{"url": f"{scheme}://[::1]:6666"}]


async def with_tls_server(certificate, check):
    certfile, keyfile = certificate
    httpserver = tornado.httpserver.HTTPServer(
        tornado.web.Application([(r"/healthcheck", server.HealthCheck)]),
        ssl_options=tls.server_context(certfile, keyfile),
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    httpserver.add_sockets(sockets)
    try:
        await check(port)
    finally:
        httpserver.stop()
        await httpserver.close_all_connections()


def test_real_https_and_tls12_rejection(certificate):
    async def check(port):
        client = tornado.httpclient.AsyncHTTPClient(force_instance=True)
        context = ssl.create_default_context(cafile=str(certificate[0]))
        try:
            response = await client.fetch(f"https://127.0.0.1:{port}/healthcheck", ssl_options=context)
            assert response.code == 200
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            with pytest.raises((ssl.SSLError, tornado.httpclient.HTTPClientError)):
                await client.fetch(f"https://127.0.0.1:{port}/healthcheck", ssl_options=context)
        finally:
            client.close()

    asyncio.run(with_tls_server(certificate, check))


def test_real_hybrid_key_exchange(certificate):
    if ssl.OPENSSL_VERSION_INFO < (3, 5):
        pytest.skip("Python needs OpenSSL 3.5+ for built-in hybrid ML-KEM groups")
    groups = subprocess.run(
        ["openssl", "list", "-tls-groups", "-tls1_3"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if groups.returncode or "X25519MLKEM768" not in groups.stdout:
        pytest.skip("openssl CLI needs hybrid ML-KEM support")

    async def check(port):
        result = await asyncio.to_thread(
            subprocess.run,
            [
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{port}",
                "-servername",
                "localhost",
                "-tls1_3",
                "-groups",
                "X25519MLKEM768",
                "-CAfile",
                str(certificate[0]),
                "-verify_return_error",
                "-verify_hostname",
                "localhost",
                "-brief",
                "-ign_eof",
                "-ignore_unexpected_eof",  # Tornado closes HTTP connections without TLS close_notify.
            ],
            input="GET /healthcheck HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "HTTP/1.1 200" in result.stdout
        assert result.stdout.endswith('{"status":true}')
        assert "TLSv1.3" in result.stderr
        assert "X25519MLKEM768" in result.stderr
        assert "Verification: OK" in result.stderr

    asyncio.run(with_tls_server(certificate, check))


def test_documented_strict_policy_rejects_classical_peer(certificate, tmp_path):
    if ssl.OPENSSL_VERSION_INFO < (3, 5):
        pytest.skip("The documented hybrid-only policy needs OpenSSL 3.5+")
    document = Path(__file__).resolve().parents[1] / "documentation/mkdocs/tls-pqc.md"
    config = tmp_path / "openssl.cnf"
    config.write_text(document.read_text().split("```ini\n", 1)[1].split("```", 1)[0])
    # OpenSSL reads configuration on initialization, so use a fresh interpreter.
    # Memory BIOs exercise real handshakes without requiring another listener.
    script = """
import ssl
import sys
from misp_modules.tls import server_context

def handshake(classical):
    context = ssl.create_default_context(cafile=sys.argv[1])
    if classical:
        context.set_ecdh_curve("X25519")
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(client_in, client_out, server_hostname="localhost")
    server = server_context(sys.argv[1], sys.argv[2]).wrap_bio(server_in, server_out, server_side=True)
    complete = [False, False]
    for _ in range(20):
        for index, (peer, output, target) in enumerate(
            [(client, client_out, server_in), (server, server_out, client_in)]
        ):
            try:
                peer.do_handshake()
                complete[index] = True
            except ssl.SSLWantReadError:
                pass
            target.write(output.read())
        if all(complete):
            assert client.version() == "TLSv1.3"
            return
    raise AssertionError("Handshake did not complete")

handshake(False)
try:
    handshake(True)
except ssl.SSLError as exc:
    assert exc.reason == "NO_SUITABLE_KEY_SHARE", exc
else:
    raise AssertionError("Classical key exchange was accepted under the strict policy")
print("Hybrid policy accepted a compatible peer and rejected X25519")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, *(str(path) for path in certificate)],
        env={**os.environ, "OPENSSL_CONF": str(config)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
