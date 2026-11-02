import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.lib import plum_island as api
from misp_modules.modules.expansion import plum_island, plum_island_search

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
CONFIG = {"url": "https://plum.example/controller", "username": "misp-reader", "password": "secret-password"}
TOKEN = "private-jwt-token"
CURSOR = "private-signed-cursor"
OBSERVATION = {
    "uid": "scan-443",
    "first_seen": 1770000000,
    "last_seen": 1770003600,
    "tags": ["product:example", "proto:https"],
    "warning": None,
    "document": {
        "id": "scan-443",
        "ip": "192.0.2.1",
        "body": {
            "ports": [
                {"portid": "443", "protocol": "tcp", "scripts": [{"id": "banner", "output": "Untrusted scan text"}]}
            ]
        },
    },
}


def query(kind="ip-dst", value="192.0.2.1", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "Original context"},
            "config": CONFIG if config is None else config,
        }
    )


def reply(data, status=200):
    response = Mock(status_code=status)
    response.json.return_value = data
    return response


def envelope(data, version=1):
    return reply({"api_version": version, "result": data})


def history(observations=None, **changes):
    return {
        "ip": "192.0.2.1",
        "hostname": "",
        "requested_hostnames": ["www.example.org"],
        "total": 1,
        "observations": [deepcopy(OBSERVATION)] if observations is None else observations,
        "time_range": None,
        "date_semantics": "selected group's full history",
        "next_offset": None,
        **changes,
    }


def search(matches=None, cursor=None, **changes):
    return {
        "status": True,
        "results": {} if matches is None else matches,
        "next_cursor": cursor,
        "timestamps": {"192.0.2.1": {"scan-443": {"first_seen": 1770000000, "last_seen": 1770003600}}},
        "requested_hostnames": {"192.0.2.1": ["www.example.org"]},
        "time_range": {"from_ts": 1770000000, "to_ts": 1770003600},
        "date_semantics": "last_seen window discovery, not full interval-overlap export",
        **changes,
    }


def handle(module, pages, **kwargs):
    with patch.object(api.requests, "post", side_effect=[reply({"access_token": TOKEN}), *pages]) as post:
        result = module.handler(query(**kwargs))
    return result, post


def evidence(result, title):
    return [json.loads(obj["Attribute"][0]["value"]) for obj in result["results"]["Object"] if obj["comment"] == title]


def assert_source(result):
    assert "results" in result, result
    original = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert original["to_ids"] is True
    assert original["comment"] == "Original context"
    for obj in result["results"]["Object"]:
        assert obj["name"] == "annotation"
        assert any(
            ref["referenced_uuid"] == UUID and ref["relationship_type"] == "describes" for ref in obj["ObjectReference"]
        )
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    assert all(a["to_ids"] is False for a in result["results"]["Attribute"] if a["uuid"] != UUID)


@pytest.mark.parametrize("module", [plum_island, plum_island_search])
def test_discovery(module):
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]
    assert module.version()["data-source"] == "external"


@pytest.mark.parametrize("module", [plum_island, plum_island_search])
@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"attribute": []}'])
def test_bad_requests_do_not_contact_service(module, raw):
    with patch.object(api.requests, "post") as post:
        assert "error" in module.handler(raw)
    post.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"url": ""},
        {"url": "http://plum.example"},
        {"url": "https://u:p@plum.example"},
        {"url": "https://plum.example?q=secret"},
        {"url": "https://plum.example/#secret"},
        {"url": "https://plum.example:0"},
        {"url": "https://plum.example:bad"},
        {"password": ""},
        {"username": []},
        {"access_token": 5},
        {"max_results": True},
        {"max_results": 0},
        {"max_results": 101},
        {"max_pages": 21},
        {"max_pages": 0},
        {"from_ts": -1},
        {"from_ts": True},
        {"to_ts": 1.5},
        {"from_ts": 20, "to_ts": 10},
    ],
)
def test_bad_configuration_does_not_contact_service(changes):
    with patch.object(api.requests, "post") as post:
        result = plum_island.handler(query(config={**CONFIG, **changes}))
    assert "error" in result
    assert "secret-password" not in str(result)
    post.assert_not_called()


@pytest.mark.parametrize(
    "module,kind,value",
    [
        (plum_island, "ip-dst", "192.0.2.0/24"),
        (plum_island, "ip-src", "fe80::1%eth0"),
        (plum_island, "hostname", "example.org"),
        (plum_island_search, "domain", "example.org OR port:443"),
        (plum_island_search, "hostname", "-bad.example.org"),
        (plum_island_search, "x509-fingerprint-sha1", "short"),
        (plum_island_search, "md5", "a" * 32),
        (plum_island_search, "ip-dst", "not-an-ip"),
    ],
)
def test_invalid_inputs_before_authentication(module, kind, value):
    with patch.object(api.requests, "post") as post:
        assert "error" in module.handler(query(kind, value))
    post.assert_not_called()


def test_history_preserves_full_uid_evidence_and_source():
    result, post = handle(plum_island, [envelope(history())])
    assert_source(result)
    assert evidence(result, "Plum Island scan observation")[0]["observation"] == OBSERVATION
    summary = evidence(result, "Plum Island IP history summary")[0]
    assert summary["requested_hostnames"] == ["www.example.org"]
    assert summary["complete"] is True
    assert summary["returned"] == 1
    assert post.call_args_list[0].args == (CONFIG["url"] + "/api/v1/security/login",)
    assert post.call_args_list[0].kwargs["json"] == {
        "username": "misp-reader",
        "password": "secret-password",
        "provider": "db",
    }
    assert post.call_args.kwargs["headers"] == {"Authorization": "Bearer " + TOKEN}
    assert post.call_args.kwargs["json"] == {"ip": "192.0.2.1", "hostname": "", "offset": 0, "limit": 25}
    for call in post.call_args_list:
        assert call.kwargs["verify"] is True
        assert call.kwargs["timeout"] == (5, 30)
        assert call.kwargs["allow_redirects"] is False


def test_ipv6_hostname_group_dates_and_missing_document():
    missing = dict(OBSERVATION, document=None, warning="document_not_found")
    result, post = handle(
        plum_island,
        [
            envelope(
                history(
                    [missing],
                    ip="2001:db8::1",
                    hostname="www.example.org",
                )
            )
        ],
        kind="ip-src",
        value="2001:0db8::1",
        config={
            **CONFIG,
            "hostname": "WWW.Example.org.",
            "from_ts": "1770000000",
            "to_ts": "1770003600",
        },
    )
    assert_source(result)
    assert evidence(result, "Plum Island scan observation")[0]["observation"]["warning"] == "document_not_found"
    assert post.call_args.kwargs["json"] == {
        "ip": "2001:db8::1",
        "hostname": "www.example.org",
        "offset": 0,
        "limit": 25,
        "from_ts": 1770000000,
        "to_ts": 1770003600,
    }


def test_history_follows_offsets_and_marks_result_cap():
    result, post = handle(
        plum_island,
        [
            envelope(history(total=3, next_offset=1)),
            envelope(history([dict(OBSERVATION, uid="other-scan")], total=3, next_offset=2)),
        ],
        config={**CONFIG, "max_results": "2"},
    )
    assert_source(result)
    assert post.call_count == 3
    assert post.call_args.kwargs["json"]["offset"] == 1
    assert post.call_args.kwargs["json"]["limit"] == 1
    assert len(evidence(result, "Plum Island scan observation")) == 2
    assert evidence(result, "Plum Island IP history summary")[0]["complete"] is False


def test_empty_selected_group_retains_hostname_choices():
    result, _ = handle(plum_island, [envelope(history([], total=0))])
    assert_source(result)
    assert not evidence(result, "Plum Island scan observation")
    assert evidence(result, "Plum Island IP history summary")[0]["requested_hostnames"] == ["www.example.org"]


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain", "Example.ORG.", "(domain:example.org OR domain_requested:example.org)"),
        ("hostname", "www.Example.org", "(fqdn:www.example.org OR fqdn_requested:www.example.org)"),
        ("domain", "éxample.org", "(domain:xn--xample-9ua.org OR domain_requested:xn--xample-9ua.org)"),
        ("ip-src", "192.0.2.1/24", "net:192.0.2.0/24"),
        ("ip-dst", "2001:db8::/48", "net:2001:db8::/48"),
        ("ip-dst", "2001:0db8::1", "ip:2001:db8::1"),
        ("x509-fingerprint-md5", "AB:" * 15 + "AB", "x509_md5:" + "ab" * 16),
        ("x509-fingerprint-sha1", "A" * 40, "x509_sha1:" + "a" * 40),
        ("x509-fingerprint-sha256", "B" * 64, "x509_sha256:" + "b" * 64),
    ],
)
def test_exact_search_mapping(kind, value, expected):
    result, post = handle(plum_island_search, [envelope(search())], kind=kind, value=value)
    assert_source(result)
    assert post.call_args.kwargs["json"]["query"] == expected


def test_search_continues_empty_windows_and_preserves_scope_without_private_cursor():
    result, post = handle(
        plum_island_search,
        [
            envelope(search(cursor=CURSOR)),
            envelope(search({"192.0.2.1": ["scan-443"], "2001:db8::1": ["scan-ipv6"]})),
        ],
        kind="domain",
        value="example.org",
        config={**CONFIG, "from_ts": 1770000000, "to_ts": 1770003600},
    )
    assert_source(result)
    assert post.call_args.kwargs["json"] == {"cursor": CURSOR, "limit": 25}
    pivots = [a for a in result["results"]["Attribute"] if a["uuid"] != UUID]
    assert {a["value"] for a in pivots} == {"192.0.2.1", "2001:db8::1"}
    pages = evidence(result, "Plum Island search evidence")
    assert pages[1]["results"]["192.0.2.1"] == ["scan-443"]
    assert pages[1]["timestamps"]["192.0.2.1"]["scan-443"]["first_seen"] == 1770000000
    assert pages[1]["time_range"]["to_ts"] == 1770003600
    assert evidence(result, "Plum Island search summary")[0]["complete"] is True
    assert CURSOR not in json.dumps(result)
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("config", [{"max_results": 1}, {"max_pages": 1}])
def test_search_budget_is_explicit(config):
    result, post = handle(
        plum_island_search,
        [envelope(search({"192.0.2.1": ["scan"]}, cursor=CURSOR))],
        kind="domain",
        value="example.org",
        config={**CONFIG, **config},
    )
    assert_source(result)
    assert post.call_count == 2
    assert evidence(result, "Plum Island search summary")[0]["complete"] is False
    assert CURSOR not in json.dumps(result)


def test_auth_token_without_password_skips_login():
    with patch.object(api.requests, "post", return_value=envelope(history())) as post:
        result = plum_island.handler(query(config={"url": CONFIG["url"], "access_token": TOKEN}))
    assert_source(result)
    post.assert_called_once()
    assert post.call_args.kwargs["headers"] == {"Authorization": "Bearer " + TOKEN}


def test_expired_jwt_reauthenticates_once():
    with patch.object(
        api.requests,
        "post",
        side_effect=[
            reply({"access_token": "expired"}),
            reply({}, 401),
            reply({"access_token": TOKEN}),
            envelope(history()),
        ],
    ) as post:
        result = plum_island.handler(query())
    assert_source(result)
    assert post.call_count == 4
    assert post.call_args.kwargs["headers"] == {"Authorization": "Bearer " + TOKEN}


def test_repeated_401_is_not_retried_forever():
    result, post = handle(plum_island, [reply({}, 401), reply({"access_token": TOKEN}), reply({}, 401)])
    assert "401" in result["error"]
    assert post.call_count == 4


@pytest.mark.parametrize("status", [301, 401, 403, 404, 410, 413, 429, 500, 503])
def test_api_errors_are_not_empty_successes_and_do_not_echo_secrets(status):
    with patch.object(api.requests, "post", return_value=reply({"message": TOKEN}, status)) as post:
        result = plum_island.handler(query(config={"url": CONFIG["url"], "access_token": TOKEN}))
    assert str(status) in result["error"]
    assert TOKEN not in str(result)
    post.assert_called_once()


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_transport_errors_are_redacted(failure):
    with patch.object(api.requests, "post", side_effect=failure(TOKEN + " secret-password")):
        result = plum_island.handler(query())
    assert "error" in result
    assert TOKEN not in str(result) and "secret-password" not in str(result)


@pytest.mark.parametrize(
    "data", [{}, {"access_token": None}, {"access_token": 123}, {"access_token": "bad\ntoken"}, []]
)
def test_invalid_login_response(data):
    with patch.object(api.requests, "post", return_value=reply(data)):
        assert "error" in plum_island.handler(query())


@pytest.mark.parametrize(
    "data",
    [{}, [], {"api_version": 2, "result": {}}, {"api_version": True, "result": {}}, {"api_version": 1, "result": []}],
)
def test_invalid_api_envelope(data):
    result, _ = handle(plum_island, [reply(data)])
    assert "error" in result


def test_invalid_json_is_redacted():
    response = reply(None)
    response.json.side_effect = ValueError(TOKEN)
    result, _ = handle(plum_island, [response])
    assert "error" in result
    assert TOKEN not in str(result)


@pytest.mark.parametrize(
    "changes",
    [
        {"ip": "192.0.2.2"},
        {"hostname": "wrong.example.org"},
        {"observations": {}},
        {"observations": [5]},
        {"total": True},
        {"requested_hostnames": "wrong"},
        {"next_offset": 0},
        {"next_offset": True},
        {"next_offset": -1},
    ],
)
def test_bad_history_shapes_and_pagination(changes):
    result, _ = handle(plum_island, [envelope(history(**changes))])
    assert "error" in result


@pytest.mark.parametrize(
    "changes",
    [
        {"status": False},
        {"results": []},
        {"results": {"bad-ip": ["uid"]}},
        {"results": {"192.0.2.1": "uid"}},
        {"next_cursor": 123},
        {"next_cursor": ""},
    ],
)
def test_bad_search_shapes_and_pagination(changes):
    result, _ = handle(plum_island_search, [envelope(search(**changes))], kind="domain", value="example.org")
    assert "error" in result


def test_repeated_cursor_is_rejected():
    result, post = handle(
        plum_island_search,
        [envelope(search(cursor=CURSOR)), envelope(search(cursor=CURSOR))],
        kind="domain",
        value="example.org",
    )
    assert "pagination" in result["error"]
    assert post.call_count == 3


@pytest.mark.parametrize(
    "module,key,page",
    [
        (plum_island, "next_offset", history()),
        (plum_island_search, "next_cursor", search()),
    ],
)
def test_missing_continuation_is_not_reported_as_complete(module, key, page):
    del page[key]
    result, _ = handle(module, [envelope(page)])
    assert "error" in result


def test_empty_window_page_budget_remains_incomplete():
    result, _ = handle(
        plum_island_search,
        [envelope(search(cursor=CURSOR))],
        kind="domain",
        value="example.org",
        config={**CONFIG, "max_pages": 1},
    )
    summary = evidence(result, "Plum Island search summary")[0]
    assert summary["returned"] == 0 and summary["complete"] is False


def test_history_page_budget_remains_incomplete():
    result, _ = handle(plum_island, [envelope(history(next_offset=1, total=2))], config={**CONFIG, "max_pages": 1})
    assert evidence(result, "Plum Island IP history summary")[0]["complete"] is False


def test_search_remaining_limit_and_duplicate_ips():
    result, post = handle(
        plum_island_search,
        [
            envelope(search({"192.0.2.1": ["scan-a"]}, cursor="first")),
            envelope(search({"192.0.2.1": ["scan-b"]}, cursor="second")),
            envelope(search({"192.0.2.2": ["scan-c"]})),
        ],
        kind="domain",
        value="example.org",
        config={**CONFIG, "max_results": 2},
    )
    assert_source(result)
    assert [call.kwargs["json"]["limit"] for call in post.call_args_list[1:]] == [2, 1, 1]
    assert len([a for a in result["results"]["Attribute"] if a["type"] == "ip-dst"]) == 2
    assert evidence(result, "Plum Island search summary")[0]["complete"] is True


def test_ip_search_retains_original_when_it_is_also_a_match():
    result, _ = handle(plum_island_search, [envelope(search({"192.0.2.1": ["scan"]}))])
    assert_source(result)


def test_later_page_failure_does_not_return_partial_success():
    result, _ = handle(
        plum_island_search,
        [envelope(search({"192.0.2.1": ["scan"]}, cursor=CURSOR)), reply({}, 503)],
        kind="domain",
        value="example.org",
    )
    assert "503" in result["error"]
    assert "results" not in result


def test_real_loader_discovers_both_modules():
    from importlib.resources import files

    import misp_modules

    discovered = {
        path.name
        for kind, path in misp_modules.iterate_modules(files(misp_modules).joinpath("modules"))
        if kind.name == "expansion"
    }
    assert {"plum_island.py", "plum_island_search.py"} <= discovered
