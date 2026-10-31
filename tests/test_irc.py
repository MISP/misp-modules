import json
import socket
import ssl
from collections import deque
from unittest.mock import Mock

import pytest

from misp_modules.modules.action_mod import irc


def workflow(**params):
    return {
        "params": {
            "irc_server": "irc.example.org",
            "irc_port": "6697",
            "use_tls": "true",
            "nickname": "misp",
            "channel": "#misp",
            "message_template": "Event: {{ Event.info }}",
            **params,
        },
        "data": {"Event": {"info": "Example event"}},
    }


class IRCConnection:
    def __init__(self):
        self.commands = []
        self.responses = deque()
        self.registration = b":server 001 misp :Welcome\r\n"
        self.join = b":misp!user@host JOIN :#misp\r\n"
        self.message_error = None
        self.disconnected = False
        self.closed = False
        self.stream_closed = False
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def makefile(self, mode):
        assert mode == "rb"
        connection = self

        class Stream:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                connection.stream_closed = True

            def readline(self, limit):
                if connection.responses:
                    return connection.responses.popleft()[:limit]
                if connection.disconnected:
                    return b""
                raise socket.timeout("private server details")

        return Stream()

    def sendall(self, data):
        assert len(data) <= 512
        assert data.endswith(b"\r\n")
        line = data[:-2].decode("utf-8")
        assert "\r" not in line and "\n" not in line
        self.commands.append(line)
        if line.startswith("USER "):
            self.responses.append(self.registration)
        elif line.startswith("JOIN "):
            self.responses.append(self.join)
        elif line.startswith("PRIVMSG ") and self.message_error:
            self.responses.append(self.message_error)
        elif line.startswith("PING "):
            self.responses.append(f":server PONG server :{line[6:]}\r\n".encode())


@pytest.fixture
def transport(monkeypatch):
    connection = IRCConnection()
    connection.connect = Mock(return_value=connection)
    connection.tls = Mock()
    connection.tls.wrap_socket.return_value = connection
    connection.context = Mock(return_value=connection.tls)
    monkeypatch.setattr(irc.socket, "create_connection", connection.connect)
    monkeypatch.setattr(irc.ssl, "create_default_context", connection.context)
    return connection


def test_tls_registration_join_send_and_quit(transport):
    assert irc.handler(json.dumps(workflow(server_password="secret", channel_key="key"))) == {"data": True}
    transport.connect.assert_called_once_with(("irc.example.org", 6697), timeout=30)
    transport.context.assert_called_once_with()
    transport.tls.wrap_socket.assert_called_once_with(transport, server_hostname="irc.example.org")
    assert transport.commands[:5] == [
        "PASS :secret",
        "NICK misp",
        "USER misp 0 * :MISP workflow",
        "JOIN #misp key",
        "PRIVMSG #misp :Event: Example event",
    ]
    assert transport.commands[5].startswith("PING :")
    assert transport.commands[-1] == "QUIT :MISP workflow complete"
    assert transport.closed and transport.stream_closed
    assert all(0 < timeout <= 30 for timeout in transport.timeouts)


def test_plaintext_custom_port_and_server_ping(transport):
    transport.responses.append(b"PING :server-token\r\n")
    assert irc.handler(json.dumps(workflow(use_tls="false", irc_port="6667"))) == {"data": True}
    transport.connect.assert_called_once_with(("irc.example.org", 6667), timeout=30)
    transport.context.assert_not_called()
    assert "PONG :server-token" in transport.commands
    assert not any(line.startswith("PASS") for line in transport.commands)


def test_matching_data_and_json_fallback(transport):
    request = workflow()
    request["matchingData"] = {"Event": {"info": "Matched"}}
    del request["data"]
    assert irc.handler(json.dumps(request)) == {"data": True}
    assert "PRIVMSG #misp :Event: Matched" in transport.commands
    transport.commands.clear()
    request["matchingData"] = {}
    request["params"].pop("message_template")
    assert irc.handler(json.dumps(request)) == {"data": True}
    assert [line for line in transport.commands if line.startswith("PRIVMSG")] == [
        "PRIVMSG #misp :```",
        "PRIVMSG #misp :{}",
        "PRIVMSG #misp :```",
    ]


def test_multiline_utf8_messages_stay_within_wire_limit(transport):
    message = "é😀" * 300 + "\r\nsecond\n/QUIT\rthird\tline"
    assert irc.handler(json.dumps(workflow(message_template=message))) == {"data": True}
    lines = [line for line in transport.commands if line.startswith("PRIVMSG")]
    text = [line.removeprefix("PRIVMSG #misp :") for line in lines]
    assert "".join(text[:-3]) == "é😀" * 300
    assert text[-3:] == ["second", "/QUIT", "third line"]
    assert all(len((line + "\r\n").encode()) <= 512 for line in lines)


@pytest.mark.parametrize(
    "reply",
    [b":server 433 * misp :Nickname taken\r\n", b"ERROR :private server details\r\n"],
)
def test_registration_rejection_prevents_join_and_send(transport, reply):
    transport.registration = reply
    result = irc.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result
    assert not any(line.startswith(("JOIN", "PRIVMSG")) for line in transport.commands)
    assert "private server details" not in json.dumps(result)
    assert transport.closed and transport.stream_closed


@pytest.mark.parametrize(
    "reply",
    [
        b":server 475 misp #misp :Bad key\r\n",
        b":server 473 misp #misp :Invite only\r\n",
        b":other!user@host JOIN :#misp\r\n",
        b":misp!user@host JOIN :#other\r\n",
    ],
)
def test_failed_or_unconfirmed_join_prevents_send(transport, reply):
    transport.join = reply
    assert irc.handler(json.dumps(workflow()))["data"] is False
    assert not any(line.startswith("PRIVMSG") for line in transport.commands)
    assert transport.closed and transport.stream_closed


def test_casemapping_and_ircv3_tagged_join(transport):
    transport.join = b"@time=now :MISP!user@host JOIN :#MISP\r\n"
    assert irc.handler(json.dumps(workflow())) == {"data": True}


def test_send_rejection_is_failure(transport):
    transport.message_error = b":server 404 misp #misp :Cannot send private details\r\n"
    result = irc.handler(json.dumps(workflow()))
    assert result["data"] is False
    assert "private details" not in json.dumps(result)
    assert transport.closed and transport.stream_closed


@pytest.mark.parametrize("error", [socket.timeout("private"), OSError("private"), ssl.SSLError("private")])
def test_connection_failure_is_sanitized_without_retry(transport, error):
    transport.connect.side_effect = error
    result = irc.handler(json.dumps(workflow()))
    assert result["data"] is False
    assert "private" not in json.dumps(result)
    transport.connect.assert_called_once()


def test_tls_failure_closes_socket(transport):
    transport.tls.wrap_socket.side_effect = ssl.SSLCertVerificationError("private certificate details")
    assert irc.handler(json.dumps(workflow()))["data"] is False
    assert transport.closed
    assert transport.commands == []


def test_disconnect_before_registration(transport):
    transport.registration = b""
    transport.disconnected = True
    assert irc.handler(json.dumps(workflow()))["data"] is False
    assert transport.closed and transport.stream_closed


def test_timeout_is_bounded_across_server_messages(transport, monkeypatch):
    times = iter([0, 0, 0, 0, 31])
    monkeypatch.setattr(irc, "monotonic", lambda: next(times))
    assert irc.handler(json.dumps(workflow()))["data"] is False
    assert not any(line.startswith("PRIVMSG") for line in transport.commands)


@pytest.mark.parametrize(
    "params",
    [
        {"irc_server": ""},
        {"irc_server": None},
        {"irc_server": "irc.example.org\r\nQUIT"},
        {"irc_port": "invalid"},
        {"irc_port": 0},
        {"irc_port": 65536},
        {"irc_port": True},
        {"use_tls": "maybe"},
        {"use_tls": 1},
        {"nickname": "bad name"},
        {"nickname": ":bad"},
        {"nickname": ""},
        {"channel": "misp"},
        {"channel": "#one,#two"},
        {"channel": "#misp\r\nQUIT"},
        {"server_password": "secret\r\nQUIT"},
        {"channel_key": "key other"},
        {"channel_key": "one,two"},
        {"message_template": []},
        {"message_template": "{% invalid %}"},
        {"message_template": "{{ missing }}"},
        {"message_template": "message\x00"},
        {"message_template": "\x01ACTION do something\x01"},
    ],
)
def test_invalid_configuration_fails_before_connection(transport, params):
    assert irc.handler(json.dumps(workflow(**params)))["data"] is False
    transport.connect.assert_not_called()


@pytest.mark.parametrize("payload", ["not JSON", "null", "[]", "{}", '{"params": []}', '{"params": {}}'])
def test_malformed_request(transport, payload):
    assert irc.handler(payload)["data"] is False
    transport.connect.assert_not_called()
    assert irc.handler() is False
