import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests
from pymisp import MISPObject

from misp_modules.modules.expansion import bgpranking

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
DAY = "2026-11-10"
FIXTURES = Path(__file__).parent / "fixtures" / "bgpranking"


def query(value="AS13335", kind="AS", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "comment": "source context", "to_ids": True},
            "config": {"date": DAY} if config is None else config,
        }
    )


def payload(name="as13335-v4"):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def response(data, status=200):
    result = Mock(status_code=status)
    result.json.return_value = data
    return result


def values(obj):
    return {attribute["object_relation"]: attribute["value"] for attribute in obj["Attribute"]}


def objects(result):
    assert "results" in result, result
    (source,) = result["results"]["Attribute"]
    assert source["uuid"] == UUID
    assert source["comment"] == "source context"
    assert source["to_ids"] is True
    result_objects = {obj["name"]: obj for obj in result["results"]["Object"]}
    for obj in result_objects.values():
        assert all(attribute["to_ids"] is False for attribute in obj["Attribute"])
        # Validate against the installed, unmodified standard object templates.
        validated = MISPObject(obj["name"], strict=True)
        validated.from_dict(**obj)
        validated.to_json()
    assert {"referenced_uuid": UUID, "relationship_type": "describes"}.items() <= (
        result_objects["asn"]["ObjectReference"][0].items()
    )
    return result_objects


@pytest.fixture
def post():
    with patch.object(bgpranking.requests, "post", return_value=response(payload())) as mock:
        yield mock


def test_discovery():
    assert bgpranking.handler(False) is False
    assert bgpranking.introspection() == {"input": ["AS"], "format": "misp_standard"}
    assert bgpranking.version()["config"] == ["date", "address_family"]
    assert bgpranking.version()["module-type"] == ["expansion", "hover"]


@pytest.mark.parametrize("value", ["AS13335", "13335", " as00013335 "])
def test_live_response_contract_and_comma_in_description(post, value):
    result = objects(bgpranking.handler(query(value)))
    assert values(result["asn"]) == {
        "asn": "AS13335",
        "description": "CLOUDFLARENET - Cloudflare, Inc.",
        "country": "US",
    }
    assert values(result["bgp-ranking"]) == {
        "ranking": 0.00040743913666121126,
        "position": "6086",
        "date": "2026-11-10T00:00:00+00:00",
        "address-family": "v4",
    }
    assert result["asn"]["ObjectReference"][1]["referenced_uuid"] == result["bgp-ranking"]["uuid"]
    assert result["asn"]["ObjectReference"][1]["relationship_type"] == "ranked-with"
    assert "14413" in result["bgp-ranking"]["comment"]
    post.assert_called_once_with(
        "https://bgpranking.circl.lu/json/asn",
        json={"asn": "13335", "date": DAY, "ipversion": "v4"},
        headers={"Accept": "application/json"},
        timeout=30,
        allow_redirects=False,
    )


@pytest.mark.parametrize("config", [{}, {"date": "", "address_family": ""}, None])
def test_default_is_yesterday_in_utc(post, config):
    raw = json.loads(query())
    raw["config"] = config
    with patch.object(bgpranking, "datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime(2026, 11, 11, 0, 30, tzinfo=timezone.utc)
        objects(bgpranking.handler(json.dumps(raw)))
        clock.now.assert_called_once_with(timezone.utc)
    assert post.call_args.kwargs["json"] == {"asn": "13335", "date": DAY, "ipversion": "v4"}


@pytest.mark.parametrize("name,value,family", [("as5577-v4", "AS5577", "v4"), ("as13335-v6", "AS13335", "v6")])
def test_unranked_asn_and_empty_daily_set(post, name, value, family):
    post.return_value = response(payload(name))
    result = objects(bgpranking.handler(query(value, config={"date": DAY, "address_family": family})))
    assert set(result) == {"asn"}
    assert "No ranking entry" in result["asn"]["comment"]
    assert "not a clean verdict" in result["asn"]["comment"]
    assert post.call_args.kwargs["json"]["ipversion"] == family


def test_ipv6_ranking_uses_requested_family(post):
    data = payload()
    data["meta"]["ipversion"] = "v6"
    post.return_value = response(data)
    result = objects(bgpranking.handler(query(config={"date": DAY, "address_family": "v6"})))
    assert values(result["bgp-ranking"])["address-family"] == "v6"


@pytest.mark.parametrize("description", [None, {}, "", "Holder without country", "Holder, unknown country"])
def test_missing_or_unsplittable_description_does_not_discard_ranking(post, description):
    data = payload()
    data["response"]["asn_description"] = description
    post.return_value = response(data)
    result = objects(bgpranking.handler(query()))
    assert "bgp-ranking" in result
    assert "country" not in values(result["asn"])
    if description:
        assert values(result["asn"])["description"] == description
    else:
        assert "description" not in values(result["asn"])


def test_unknown_asn_returns_context_without_inventing_reputation(post):
    data = payload("as5577-v4")
    data["meta"]["asn"] = "4294967294"
    data["response"]["asn_description"] = {}
    post.return_value = response(data)
    result = objects(bgpranking.handler(query("AS4294967294")))
    assert set(result) == {"asn"}
    assert values(result["asn"]) == {"asn": "AS4294967294"}


def test_ranked_zero_score_is_preserved(post):
    data = payload()
    data["response"]["ranking"]["rank"] = 0
    post.return_value = response(data)
    result = objects(bgpranking.handler(query()))
    assert float(values(result["bgp-ranking"])["ranking"]) == 0


@pytest.mark.parametrize(
    "raw",
    ["{", "[]", "null", "{}", '{"attribute": []}', '{"attribute": {"type": "AS", "value": "13335"}}'],
)
def test_invalid_envelope(post, raw):
    assert "error" in bgpranking.handler(raw)
    post.assert_not_called()


@pytest.mark.parametrize("value", ["", " ", "AS-1", "AS4294967296", "1.5", "AS", "AS１２３", [], 13335, True])
def test_invalid_asn(post, value):
    assert "error" in bgpranking.handler(query(value))
    post.assert_not_called()


def test_unsupported_type(post):
    assert "error" in bgpranking.handler(query(kind="ip-dst", value="1.1.1.1"))
    post.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        [],
        False,
        "invalid",
        {"date": "2026-02-30"},
        {"date": "20261110"},
        {"date": 20261110},
        {"date": "2026-11-10T00:00:00Z"},
        {"address_family": "ipv6"},
        {"address_family": []},
    ],
)
def test_invalid_config(post, config):
    assert "error" in bgpranking.handler(query(config=config))
    post.assert_not_called()


@pytest.mark.parametrize("error", [requests.Timeout, requests.ConnectionError])
def test_transport_failure(post, error):
    post.side_effect = error("private transport details")
    result = bgpranking.handler(query())
    assert "failed or timed out" in result["error"]
    assert "private transport details" not in result["error"]


@pytest.mark.parametrize("status", [301, 400, 429, 500, 503])
def test_http_failure(post, status):
    post.return_value = response(payload(), status)
    assert str(status) in bgpranking.handler(query())["error"]


def test_invalid_json(post):
    post.return_value.json.side_effect = ValueError("not JSON")
    assert "invalid JSON" in bgpranking.handler(query())["error"]


@pytest.mark.parametrize("data", [None, [], {}, {"error": "service failure"}, {"meta": {}, "response": {}}])
def test_invalid_api_envelope(post, data):
    post.return_value = response(data)
    assert "error" in bgpranking.handler(query())


@pytest.mark.parametrize("key,value", [("asn", "5577"), ("date", "2026-11-09"), ("ipversion", "v6")])
def test_unexpected_query_metadata(post, key, value):
    data = payload()
    data["meta"][key] = value
    post.return_value = response(data)
    assert "error" in bgpranking.handler(query())


@pytest.mark.parametrize(
    "key,value",
    [
        ("rank", None),
        ("rank", "0.5"),
        ("rank", True),
        ("rank", -1),
        ("rank", float("nan")),
        ("rank", float("inf")),
        ("position", None),
        ("position", 0),
        ("position", True),
        ("position", 14414),
        ("position", "1"),
        ("total_known_asns", -1),
        ("total_known_asns", True),
    ],
)
def test_invalid_ranking(post, key, value):
    data = payload()
    data["response"]["ranking"][key] = value
    post.return_value = response(data)
    assert "error" in bgpranking.handler(query())


@pytest.mark.parametrize("key", ["rank", "position", "total_known_asns"])
def test_incomplete_ranking_is_not_treated_as_unranked(post, key):
    data = payload("as5577-v4")
    del data["response"]["ranking"][key]
    post.return_value = response(data)
    assert "error" in bgpranking.handler(query("AS5577"))


@pytest.mark.parametrize(
    "key,value", [("ranking", None), ("asn_description", []), ("asn_description", {"unexpected": "data"})]
)
def test_invalid_response_fields(post, key, value):
    data = payload()
    data["response"][key] = value
    post.return_value = response(data)
    assert "error" in bgpranking.handler(query())


def test_error_does_not_poison_next_request(post):
    post.side_effect = [response({"error": "temporary failure"}), response(copy.deepcopy(payload()))]
    assert "error" in bgpranking.handler(query())
    objects(bgpranking.handler(query()))
