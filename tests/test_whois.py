import json
from unittest.mock import MagicMock, patch

from misp_modules.modules.expansion import whois

RECORD = b"domain: circl.lu\nregistrar: EuroDNS\n"


def _socket(recv=(RECORD, b"")):
    sock = MagicMock()
    sock.recv.side_effect = list(recv)
    mock = MagicMock()
    mock.return_value.__enter__.return_value = sock
    return mock, sock


def _run(request, recv=(RECORD, b""), side_effect=None):
    mock, sock = _socket(recv)
    if side_effect is not None:
        sock.connect.side_effect = side_effect
    with patch.object(whois.socket, "socket", mock):
        return whois.handler(json.dumps(request)), sock


def test_returns_the_record():
    result, sock = _run({"module": "whois", "domain": "circl.lu", "config": {"server": "127.0.0.1", "port": "4243"}})
    assert result["results"][0]["values"] == RECORD.decode()
    assert sock.connect.call_args.args[0] == ("127.0.0.1", 4243)


def test_a_request_without_event_id_no_longer_returns_none():
    # The handler used to run only when the request carried an event_id and
    # fall off the end returning None otherwise.
    request = {"module": "whois", "domain": "circl.lu", "config": {"server": "127.0.0.1", "port": "4243"}}
    assert "event_id" not in request
    result, _ = _run(request)
    assert isinstance(result, dict)
    assert "results" in result


def test_a_request_with_event_id_behaves_the_same():
    request = {
        "module": "whois",
        "domain": "circl.lu",
        "event_id": 1,
        "config": {"server": "127.0.0.1", "port": "4243"},
    }
    result, _ = _run(request)
    assert result["results"][0]["values"] == RECORD.decode()


def test_port_only_config_is_an_error_not_a_keyerror():
    result, _ = _run({"module": "whois", "domain": "circl.lu", "config": {"port": "4243"}})
    assert result["error"] == "Whois local instance address is missing"


def test_server_only_config_is_an_error():
    result, _ = _run({"module": "whois", "domain": "circl.lu", "config": {"server": "127.0.0.1"}})
    assert result["error"] == "Whois local instance address is missing"


def test_missing_config_is_an_error():
    result, _ = _run({"module": "whois", "domain": "circl.lu"})
    assert result["error"] == "Whois local instance address is missing"


def test_unreachable_instance_is_reported():
    result, _ = _run(
        {"module": "whois", "domain": "circl.lu", "config": {"server": "127.0.0.1", "port": "4243"}},
        side_effect=ConnectionRefusedError("refused"),
    )
    assert result["error"].startswith("Not able to reach the uwhois instance at 127.0.0.1:4243")


def test_unsupported_attribute_type_is_an_error():
    result, _ = _run({"module": "whois", "md5": "d41d8cd98f00b204e9800998ecf8427e", "config": {}})
    assert result["error"] == "Unsupported attributes type"


def test_description_points_at_rdap():
    assert "rdap" in whois.moduleinfo["description"]
    assert whois.introspection() == whois.mispattributes


def test_output_stays_freetext():
    """Not misp_standard. MISP runs its freetext importer over the answer, and a
    whois record is full of what that importer extracts; an object carrying the
    record as one text attribute would extract nothing."""
    assert whois.mispattributes["output"] == ["freetext"]
    assert "format" not in whois.mispattributes
