import json
from unittest.mock import Mock, call, patch

import pytest
import requests

from misp_modules.modules.expansion import apivoid
from tests import test_expansions

UUID = "ea89a33b-4ab7-4515-9f02-922a0bee333d"
APIKEY = "test-api-key"
# Representative v2 responses from https://docs.apivoid.com/ (only fields used by the module).
DNS = {
    "host": "example.com",
    "records": {
        "a": [{"target": "93.184.215.14", "ttl": 3380}],
        "aaaa": [{"target": "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "ttl": 3380}],
        "mx": [{"pref": 10, "target": "alt1.gmail-smtp-in.l.google.com", "ttl": 2700}],
        "ns": [{"target": "b.iana-servers.net", "ttl": 86180}],
    },
    "elapsed_ms": 28,
}
SSL = {
    "host": "example.com",
    "port": 443,
    "certificate": {
        "found": True,
        "fingerprint_sha1": "6f55d7d0b407cb6bb13bd14a1cbb105c0ee5c3d5",
        "fingerprint_sha256": "faf941ad6b7339463bcea590e77e39f7930a168eb6d130d79c3be12c5de83894",
        "details": {
            "subject": {"name": "CN=example.com"},
            "issuer": {"common_name": "DigiCert EV RSA CA G2"},
            "signature": {"serial": "14728578715614846917259483520735530892"},
            "validity": {
                "valid_from": "Mon, 26 Aug 2024 00:00:00 UTC",
                "valid_to": "Mon, 25 Aug 2025 23:59:59 UTC",
            },
        },
    },
    "elapsed_ms": 289,
}
NO_CERTIFICATE = {"host": "example.com", "certificate": {"found": False, "debug_message": "Connection failed"}}
EMAIL = {
    "email": "a1k5z0a3@yopmail.com",
    "username": "a1k5z0a3",
    "domain": "yopmail.com",
    "valid_format": True,
    "role_address": False,
    "suspicious_username": False,
    "dirty_words_username": False,
    "suspicious_email": False,
    "valid_tld": True,
    "disposable": True,
    "has_a_records": True,
    "has_mx_records": True,
    "has_spf_records": True,
    "dmarc_configured": True,
    "dmarc_enforced": True,
    "is_spoofable": False,
    "free_email": False,
    "russian_free_email": False,
    "china_free_email": False,
    "suspicious_domain": False,
    "dirty_words_domain": False,
    "domain_popular": False,
    "risky_tld": False,
    "police_domain": False,
    "government_domain": False,
    "educational_domain": False,
    "should_block": True,
    "score": 0,
    "elapsed_ms": 3,
}


def _response(payload, status=200, headers=None):
    return Mock(status_code=status, headers=headers or {}, json=Mock(return_value=payload))


def _query(type_="domain", value="example.com", config=None, comment=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    if comment:
        attribute["comment"] = comment
    return json.dumps({"attribute": attribute, "config": {"apikey": APIKEY} if config is None else config})


def _attributes(misp_object):
    return {attribute["object_relation"]: attribute["value"] for attribute in misp_object["Attribute"]}


@pytest.mark.parametrize("type_", ["domain", "hostname"])
def test_domain_v2_requests_and_misp_objects(type_):
    with patch.object(apivoid.requests, "post", side_effect=[_response(DNS), _response(SSL)]) as post:
        result = apivoid.handler(_query(type_=type_))["results"]

    # Exactly two POSTs: no legacy stats request and no key/target in a query string.
    assert post.call_args_list == [
        call(
            "https://api.apivoid.com/v2/dns-lookup",
            headers={"X-API-Key": APIKEY},
            json={"host": "example.com", "dns_types": "A,AAAA,MX,NS"},
            timeout=30,
        ),
        call(
            "https://api.apivoid.com/v2/ssl-info",
            headers={"X-API-Key": APIKEY},
            json={"host": "example.com"},
            timeout=60,
        ),
    ]
    assert result["Attribute"][0]["uuid"] == UUID
    objects = result["Object"]
    assert [obj["name"] for obj in objects] == ["dns-record"] * 4 + ["x509"]
    for obj, (relation, value, relationship) in zip(
        objects[:4],
        [
            ("a-record", "93.184.215.14", "resolution-of"),
            ("aaaa-record", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "resolution-of"),
            ("mx-record", "alt1.gmail-smtp-in.l.google.com", "mail-server-of"),
            ("ns-record", "b.iana-servers.net", "server-name-of"),
        ],
    ):
        assert _attributes(obj) == {"queried-domain": "example.com", relation: value}
        reference = obj["ObjectReference"][0]
        assert (reference["referenced_uuid"], reference["relationship_type"]) == (UUID, relationship)
    certificate = objects[-1]
    assert _attributes(certificate) == {
        "x509-fingerprint-sha1": SSL["certificate"]["fingerprint_sha1"],
        "x509-fingerprint-sha256": SSL["certificate"]["fingerprint_sha256"],
        "subject": "CN=example.com",
        "issuer": "DigiCert EV RSA CA G2",
        "serial-number": "14728578715614846917259483520735530892",
        "validity-not-before": "2024-08-26T00:00:00+00:00",
        "validity-not-after": "2025-08-25T23:59:59+00:00",
    }
    assert certificate["ObjectReference"][0]["referenced_uuid"] == UUID
    assert certificate["ObjectReference"][0]["relationship_type"] == "seen-by"


def test_dns_uses_response_host_and_all_records():
    dns = {"host": "canonical.example.com", "records": {"a": [{"target": "192.0.2.1"}, {"target": "192.0.2.2"}]}}
    with patch.object(apivoid.requests, "post", side_effect=[_response(dns), _response(NO_CERTIFICATE)]):
        objects = apivoid.handler(_query())["results"]["Object"]
    assert [_attributes(obj) for obj in objects] == [
        {"queried-domain": "canonical.example.com", "a-record": "192.0.2.1"},
        {"queried-domain": "canonical.example.com", "a-record": "192.0.2.2"},
    ]


@pytest.mark.parametrize(
    "dns", [DNS, {"host": "example.com", "records": {}}, {"host": "example.com", "records": {"a": []}}]
)
def test_certificate_not_found_and_empty_dns(dns):
    with patch.object(apivoid.requests, "post", side_effect=[_response(dns), _response(NO_CERTIFICATE)]):
        result = apivoid.handler(_query())["results"]
    assert result["Attribute"][0]["uuid"] == UUID
    assert all(obj["name"] == "dns-record" for obj in result["Object"])
    assert len(result["Object"]) == (4 if dns == DNS else 0)


@pytest.mark.parametrize(
    "type_", [type_ for type_ in apivoid.mispattributes["input"] if type_ not in ("domain", "hostname")]
)
def test_email_v2_request_and_boolean_values(type_):
    with patch.object(apivoid.requests, "post", return_value=_response(EMAIL)) as post:
        result = apivoid.handler(_query(type_, EMAIL["email"]))["results"]
    post.assert_called_once_with(
        "https://api.apivoid.com/v2/email-verify",
        headers={"X-API-Key": APIKEY},
        json={"email": EMAIL["email"]},
        timeout=30,
    )
    (obj,) = result["Object"]
    assert obj["name"] == "apivoid-email-verification"
    attributes = _attributes(obj)
    assert attributes["email"] == EMAIL["email"]
    assert attributes["username"] == EMAIL["username"]
    assert attributes["domain"] == EMAIL["domain"]
    assert float(attributes["score"]) == 0
    for key, value in EMAIL.items():
        if isinstance(value, bool):
            assert attributes[key] is value
    assert len([a for a in obj["Attribute"] if a["object_relation"] == "suspicious_email"]) == 1
    assert obj["ObjectReference"][0]["referenced_uuid"] == UUID


def test_email_special_characters_are_sent_in_json():
    email = "user+tag&name@example.com"
    with patch.object(apivoid.requests, "post", return_value=_response({**EMAIL, "email": email})) as post:
        apivoid.handler(_query("email", email))
    assert post.call_args.kwargs["json"] == {"email": email}


def test_prepared_request_uses_json_and_header_authentication():
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(EMAIL).encode()
    with patch.object(requests.Session, "send", return_value=response) as send:
        result = apivoid.handler(_query("email", EMAIL["email"]))
    assert "results" in result
    request = send.call_args.args[0]
    assert request.method == "POST"
    assert request.url == "https://api.apivoid.com/v2/email-verify"
    assert request.headers["X-API-Key"] == APIKEY
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.body) == {"email": EMAIL["email"]}


@pytest.mark.parametrize(
    "status, message", [(401, "API key is not valid"), (403, "Insufficient credits"), (500, "Server error")]
)
@pytest.mark.parametrize("type_, service", [("domain", "dns-lookup"), ("email", "email-verify")])
def test_api_errors_return_misp_errors(status, message, type_, service):
    with patch.object(apivoid.requests, "post", return_value=_response({"error": message}, status)) as post:
        result = apivoid.handler(_query(type_))
    assert result == {"error": f"APIVoid {service} error (HTTP {status}): {message}"}
    assert post.call_count == 1


def test_rate_limit_exposes_retry_after_without_retrying_the_hover():
    with patch.object(
        apivoid.requests, "post", return_value=_response({"error": "Rate limited"}, 429, {"Retry-After": "5"})
    ) as post:
        result = apivoid.handler(_query())
    assert result == {"error": "APIVoid dns-lookup error (HTTP 429): Rate limited Retry after 5 seconds."}
    assert post.call_count == 1


@pytest.mark.parametrize(
    "error", [requests.Timeout(APIKEY), requests.ConnectionError(APIKEY), requests.exceptions.InvalidHeader(APIKEY)]
)
def test_request_failures_do_not_expose_the_key(error):
    with patch.object(apivoid.requests, "post", side_effect=error):
        result = apivoid.handler(_query())
    assert "error" in result
    assert "APIVoid dns-lookup" in result["error"]
    assert APIKEY not in result["error"]


def test_api_error_redacts_key():
    with patch.object(apivoid.requests, "post", return_value=_response({"error": f"Invalid key: {APIKEY}"}, 401)):
        result = apivoid.handler(_query())
    assert APIKEY not in result["error"]


def test_invalid_json_returns_misp_error():
    response = _response(None)
    response.json.side_effect = requests.JSONDecodeError("Invalid JSON", "", 0)
    with patch.object(apivoid.requests, "post", return_value=response):
        result = apivoid.handler(_query())
    assert result == {"error": "APIVoid dns-lookup returned invalid JSON (HTTP 200)."}


@pytest.mark.parametrize("payload", [[], None, {}, {"records": []}, {"host": "example.com", "records": {"a": [{}]}}])
def test_malformed_dns_response_returns_misp_error(payload):
    with patch.object(apivoid.requests, "post", return_value=_response(payload)):
        result = apivoid.handler(_query())
    assert "unexpected response format" in result["error"]


@pytest.mark.parametrize(
    "payload", [{}, {"data": EMAIL}, {key: value for key, value in EMAIL.items() if key != "email"}]
)
def test_malformed_email_response_returns_misp_error(payload):
    with patch.object(apivoid.requests, "post", return_value=_response(payload)):
        result = apivoid.handler(_query("email", EMAIL["email"]))
    assert "unexpected response format" in result["error"]


@pytest.mark.parametrize("failure", [_response({"error": "Server error"}, 503), requests.Timeout()])
@pytest.mark.parametrize("comment", [None, "Original comment"])
def test_ssl_failure_preserves_dns_and_reports_partial_result(failure, comment):
    with patch.object(apivoid.requests, "post", side_effect=[_response(DNS), failure]):
        result = apivoid.handler(_query(comment=comment))["results"]
    assert len(result["Object"]) == 4
    prefix = "Original comment\n" if comment else ""
    assert result["Attribute"][0]["comment"].startswith(f"{prefix}APIVoid ssl-info")


def test_ssl_failure_without_dns_returns_error():
    with patch.object(
        apivoid.requests,
        "post",
        side_effect=[_response({"host": "example.com", "records": {}}), _response({"error": "Server error"}, 503)],
    ):
        result = apivoid.handler(_query())
    assert result == {"error": "APIVoid ssl-info error (HTTP 503): Server error"}


@pytest.mark.parametrize(
    "query, message",
    [
        (_query(config={}), "An API key for APIVoid is required."),
        (_query("ip-src", "192.0.2.1"), "Unsupported attribute type."),
        (json.dumps({"config": {"apikey": APIKEY}}), "type, a value and an uuid"),
    ],
)
def test_invalid_input_does_not_call_api(query, message):
    with patch.object(apivoid.requests, "post") as post:
        result = apivoid.handler(query)
    assert message in result["error"]
    post.assert_not_called()


@pytest.mark.parametrize("scenario", ["no-key", "success", "no-credits"])
def test_existing_expansion_smoke_accepts_v2_response_contract(scenario):
    case = test_expansions.TestExpansions(methodName="test_apivoid")
    case.setUp()
    case.configs = {} if scenario == "no-key" else {"apivoid": {"apikey": APIKEY}}
    responses = (
        [_response({"error": "Insufficient credits"}, 403)]
        if scenario == "no-credits"
        else [_response(DNS), _response(SSL)]
    )

    def post(query):
        return _response(apivoid.handler(json.dumps(query)))

    with (
        patch.object(apivoid.requests, "post", side_effect=responses),
        patch.object(case, "misp_modules_post", side_effect=post),
    ):
        case.test_apivoid()
