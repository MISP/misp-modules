import json
import socket
import ssl
from pathlib import Path
from unittest.mock import Mock

import pytest
import urllib3
from pymisp import MISPObject

import misp_modules
from misp_modules.modules.expansion import url_shortener as module

SOURCE_UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SHORT_URL = "https://bit.ly/example"
DESTINATION = "https://example.org/article?q=1"


def query(value=SHORT_URL, config=None, **overrides):
    attribute = {
        "type": "url",
        "value": value,
        "uuid": SOURCE_UUID,
        "to_ids": True,
        "comment": "original context",
        "Tag": [{"name": "tlp:amber"}],
    }
    attribute.update(overrides)
    return json.dumps({"attribute": attribute, "config": config})


def dns(address="93.184.216.34"):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]


@pytest.fixture
def network(monkeypatch):
    resolver = Mock(return_value=dns())
    monkeypatch.setattr(module.socket, "getaddrinfo", resolver)
    pools = []

    def factory(*args, **kwargs):
        pool = Mock()
        pools.append(pool)
        return pool

    http = Mock(side_effect=factory)
    https = Mock(side_effect=factory)
    monkeypatch.setattr(module.urllib3, "HTTPConnectionPool", http)
    monkeypatch.setattr(module.urllib3, "HTTPSConnectionPool", https)

    def replies(*items):
        responses = [
            Mock(status=status, headers={"Location": location} if location is not None else {})
            for status, location in items
        ]
        index = 0

        def response_factory(*args, **kwargs):
            nonlocal index
            pool = factory(*args, **kwargs)
            pool.urlopen.return_value = responses[index]
            index += 1
            return pool

        http.side_effect = https.side_effect = response_factory
        return responses

    return Mock(resolver=resolver, http=http, https=https, pools=pools, replies=replies)


def values(result):
    assert "results" in result, result
    return {attr["object_relation"]: attr["value"] for attr in result["results"]["Object"][0]["Attribute"]}


def assert_closed(network, replies):
    for pool, reply in zip(network.pools, replies):
        reply.close.assert_called_once()
        reply.read.assert_not_called()
        pool.close.assert_called_once()


def test_expansion_preserves_source_and_validates_standard_template(network):
    replies = network.replies((301, "/next"), (302, DESTINATION), (200, None))
    result = module.handler(query())
    assert values(result)["shortened-url"] == SHORT_URL
    assert values(result)["redirect-url"] == DESTINATION
    assert values(result)["domain"] == "bit.ly"
    history = json.loads(values(result)["text"])["redirects"]
    assert history == [
        {"url": SHORT_URL, "redirect-url": "https://bit.ly/next", "status": 301, "method": "HEAD"},
        {"url": "https://bit.ly/next", "redirect-url": DESTINATION, "status": 302, "method": "HEAD"},
    ]
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == SOURCE_UUID
    assert source["value"] == SHORT_URL
    assert source["to_ids"] is True
    assert source["comment"] == "original context"
    assert source["Tag"][0]["name"] == "tlp:amber"
    obj = result["results"]["Object"][0]
    assert obj["name"] == "shortened-link"
    assert obj["template_uuid"] == "361c0ae8-68bd-11e8-adc0-fa7ae01bbebc"
    assert all(attr["to_ids"] is False for attr in obj["Attribute"])
    assert obj["ObjectReference"][0]["referenced_uuid"] == SOURCE_UUID
    assert obj["ObjectReference"][0]["relationship_type"] == "derived-from"
    strict = MISPObject("shortened-link", strict=True)
    strict.from_dict(**obj)
    strict._validate()
    assert_closed(network, replies)


def test_dns_is_pinned_tls_verified_and_only_headers_are_requested(network):
    replies = network.replies((302, DESTINATION), (200, None))
    module.handler(query(config={"timeout": "7"}))
    assert network.https.call_args_list[0].args == ("93.184.216.34", 443)
    options = network.https.call_args_list[0].kwargs
    assert options["assert_hostname"] == options["server_hostname"] == "bit.ly"
    assert options["cert_reqs"] == ssl.CERT_REQUIRED
    assert options["ca_certs"] == module.certifi.where()
    assert network.resolver.call_count == 2
    args = network.pools[0].urlopen.call_args
    assert args.args == ("HEAD", "/example")
    assert args.kwargs["headers"]["Host"] == "bit.ly"
    assert args.kwargs["timeout"].total == 7
    assert args.kwargs["redirect"] is False
    assert args.kwargs["retries"] is False
    assert args.kwargs["preload_content"] is False
    assert "Authorization" not in args.kwargs["headers"]
    assert "Cookie" not in args.kwargs["headers"]
    assert_closed(network, replies)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_all_http_redirect_statuses(network, status):
    network.replies((status, DESTINATION), (204, None))
    assert values(module.handler(query()))["redirect-url"] == DESTINATION


@pytest.mark.parametrize("status", [405, 501])
def test_head_fallback_get_and_cleanup(network, status):
    replies = network.replies((status, None), (302, DESTINATION), (status, None), (200, None))
    result = module.handler(query())
    assert values(result)["redirect-url"] == DESTINATION
    assert json.loads(values(result)["text"])["redirects"][0]["method"] == "GET"
    assert [pool.urlopen.call_args.args[0] for pool in network.pools] == ["HEAD", "GET", "HEAD", "GET"]
    assert_closed(network, replies)


def test_additional_shortener_and_cross_scheme_relative_location(network):
    network.replies((302, "//example.org/destination"), (200, None))
    result = module.handler(
        query("http://GO.EXAMPLE./id", config={"additional_shorteners": " go.example, other.example "})
    )
    assert values(result)["redirect-url"] == "http://example.org/destination"
    assert network.http.call_count == 2
    assert network.https.call_count == 0


def test_idna_and_fragment_inheritance(network):
    network.replies((302, "https://bücher.example/ä?q=ö"), (200, None))
    result = module.handler(query(SHORT_URL + "#part"))
    assert values(result)["redirect-url"] == "https://xn--bcher-kva.example/%C3%A4?q=%C3%B6#part"
    assert network.pools[-1].urlopen.call_args.args[1] == "/%C3%A4?q=%C3%B6"


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("faß.de", "xn--fa-hia.de"),
        ("FAẞ.DE.", "xn--fa-hia.de"),
        ("βόλος.gr", "xn--nxasmm1c.gr"),
        ("ＦＡＳＳ.de", "fass.de"),
    ],
)
@pytest.mark.parametrize("custom_shortener", [False, True])
def test_uts46_hostnames_used_consistently_for_dns_host_and_tls(network, hostname, expected, custom_shortener):
    target = f"https://{hostname}/article"
    network.replies((302, DESTINATION if custom_shortener else target), (200, None))
    if custom_shortener:
        result = module.handler(query(target, config={"additional_shorteners": hostname}))
        hop = 0
        assert values(result)["domain"] == expected
        assert values(result)["shortened-url"] == target
    else:
        result = module.handler(query())
        hop = 1
        assert values(result)["redirect-url"] == f"https://{expected}/article"
    assert "results" in result, result
    assert network.resolver.call_args_list[hop].args == (expected, 443)
    assert network.https.call_args_list[hop].kwargs["server_hostname"] == expected
    assert network.https.call_args_list[hop].kwargs["assert_hostname"] == expected
    assert network.pools[hop].urlopen.call_args.kwargs["headers"]["Host"] == expected


def test_uts46_allowlist_does_not_confuse_sharp_s_with_ss(network):
    result = module.handler(query("https://faß.de/id", config={"additional_shorteners": "fass.de"}))
    assert "Unknown URL shortener" in result["error"]
    network.resolver.assert_not_called()


@pytest.mark.parametrize("hostname", ["fa\u200dss.de", "fa\u200css.de", "xn--.example"])
@pytest.mark.parametrize("source", ["url", "config", "redirect"])
def test_invalid_idna_labels_rejected_before_dns(network, hostname, source):
    if source == "redirect":
        replies = network.replies((302, f"https://{hostname}/article"))
        result = module.handler(query())
        assert network.resolver.call_count == len(network.pools) == 1
        assert_closed(network, replies)
    else:
        # Exercise the URL and configured allowlist separately so neither path
        # can silently discard a joiner or accept an invalid A-label.
        url = f"https://{hostname}/id" if source == "url" else SHORT_URL
        config = {"additional_shorteners": hostname} if source == "config" else None
        result = module.handler(query(url, config=config))
        network.resolver.assert_not_called()
    assert "error" in result
    assert "results" not in result


def test_explicit_fragment_replaces_original(network):
    network.replies((302, DESTINATION + "#new"), (200, None))
    assert values(module.handler(query(SHORT_URL + "#old")))["redirect-url"] == DESTINATION + "#new"


@pytest.mark.parametrize("location", [SHORT_URL, SHORT_URL + "#another", "https://BIT.LY:443/example"])
def test_loop_detection(network, location):
    network.replies((302, location))
    assert "loop" in module.handler(query())["error"]
    assert len(network.pools) == 1


def test_limit_allows_exact_number_of_redirects(network):
    network.replies((302, "/next"), (200, None))
    assert values(module.handler(query(config={"max_redirects": "1"})))["redirect-url"] == "https://bit.ly/next"


def test_redirect_limit_does_not_contact_extra_destination(network):
    replies = network.replies((302, "/next"), (302, DESTINATION))
    assert "max_redirects" in module.handler(query(config={"max_redirects": 1}))["error"]
    assert len(network.pools) == 2
    assert_closed(network, replies)


@pytest.mark.parametrize(
    "status,location,error",
    [
        (200, None, "did not return"),
        (404, None, "HTTP 404"),
        (503, None, "HTTP 503"),
        (302, None, "Location"),
        (302, "", "Location"),
    ],
)
def test_no_redirect_or_unusable_response(network, status, location, error):
    replies = network.replies((status, location))
    result = module.handler(query())
    assert error in result["error"]
    assert "results" not in result
    assert_closed(network, replies)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "ff02::1",
    ],
)
def test_private_and_special_dns_never_connected(network, address):
    network.resolver.return_value = dns(address)
    assert "public unicast" in module.handler(query())["error"]
    network.https.assert_not_called()


def test_mixed_dns_answers_are_rejected(network):
    network.resolver.return_value = dns() + dns("10.0.0.1")
    assert "public unicast" in module.handler(query())["error"]
    network.https.assert_not_called()


@pytest.mark.parametrize(
    "location", ["http://127.0.0.1/", "https://internal.example/", "https://169.254.169.254/latest/meta-data/"]
)
def test_redirect_target_revalidated(network, location):
    replies = network.replies((302, location))
    network.resolver.side_effect = [dns(), dns("127.0.0.1")]
    assert "public unicast" in module.handler(query())["error"]
    assert len(network.pools) == 1
    assert_closed(network, replies)


def test_fallback_dns_rebinding_is_rejected(network):
    replies = network.replies((405, None))
    network.resolver.side_effect = [dns(), dns("127.0.0.1")]
    assert "public unicast" in module.handler(query())["error"]
    assert len(network.pools) == 1
    assert_closed(network, replies)


@pytest.mark.parametrize("error", [socket.gaierror(), OSError()])
def test_dns_failure(network, error):
    network.resolver.side_effect = error
    assert "could not be resolved" in module.handler(query())["error"]
    network.https.assert_not_called()


def test_public_ipv6_target_uses_brackets_in_host_header(network):
    network.replies((302, "https://[2606:4700:4700::1111]/"), (200, None))
    network.resolver.side_effect = [dns(), dns("2606:4700:4700::1111")]
    assert values(module.handler(query()))["redirect-url"] == "https://[2606:4700:4700::1111]/"
    assert network.pools[-1].urlopen.call_args.kwargs["headers"]["Host"] == "[2606:4700:4700::1111]"


@pytest.mark.parametrize(
    "error",
    [
        urllib3.exceptions.ReadTimeoutError(None, "/", "timeout"),
        urllib3.exceptions.SSLError("bad cert"),
        OSError("connection failed"),
    ],
)
def test_network_failure_closes_pool(network, error):
    network.replies((200, None))
    pool = Mock()
    pool.urlopen.side_effect = error
    network.https.side_effect = None
    network.https.return_value = pool
    assert "failed or timed out" in module.handler(query())["error"]
    pool.close.assert_called_once()


@pytest.mark.parametrize(
    "value", ["https://example.org/", "https://bit.ly.evil.example/", "https://sub.bit.ly/", "https://notbit.ly/"]
)
def test_unknown_and_lookalike_shorteners_do_not_query_dns(network, value):
    assert "Unknown URL shortener" in module.handler(query(value))["error"]
    network.resolver.assert_not_called()


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        [],
        "",
        "bit.ly/id",
        "file:///etc/passwd",
        "https:///x",
        "https://user:pass@bit.ly/x",
        "https://@bit.ly/x",
        "https://bit.ly:0/x",
        "https://bit.ly:/x",
        "https://bit.ly:8443/x",
        "https://bit.ly:bad/x",
        "https://bit.ly/x\n",
        "https://bit.ly/white space",
        "https://bit.ly/\\evil",
        "https://%62it.ly/",
        "https://[bad]/",
        "https://bit..ly/",
        "https://bit.ly/" + "x" * 8192,
    ],
)
def test_bad_urls_do_not_query_dns(network, value):
    assert "error" in module.handler(query(value))
    network.resolver.assert_not_called()


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "https://user:pass@example.org/",
        "http://example.org:22/",
        "https://example.org/\\x",
        "https://example.org/\r\nx",
    ],
)
def test_bad_redirect_urls_do_not_connect(network, location):
    replies = network.replies((302, location))
    assert "error" in module.handler(query())
    assert len(network.pools) == 1
    assert_closed(network, replies)


@pytest.mark.parametrize(
    "config",
    [
        [],
        "bad",
        {"max_redirects": 0},
        {"max_redirects": 21},
        {"timeout": True},
        {"timeout": 31},
        {"timeout": "nan"},
        {"timeout": 1.5},
        {"additional_shorteners": []},
        {"additional_shorteners": "https://example.org"},
        {"additional_shorteners": "*.example.org"},
        {"additional_shorteners": "one.example,,two.example"},
    ],
)
def test_bad_config_does_not_query_dns(network, config):
    assert "error" in module.handler(query(config=config))
    network.resolver.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {"type": "url"}}'])
def test_invalid_requests(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("attribute", [{"type": "domain"}, {"uuid": None}, {"uuid": 1}, {"uuid": "invalid"}])
def test_bad_attributes_do_not_query_dns(network, attribute):
    assert "error" in module.handler(query(**attribute))
    network.resolver.assert_not_called()


def test_module_metadata_and_discovery():
    assert module.handler() is False
    assert module.introspection() == {"input": ["url"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]
    modules_path = module.__file__.rsplit("/expansion/", 1)[0]
    assert any(path.name == "url_shortener.py" for _, path in misp_modules.iterate_modules(Path(modules_path)))
