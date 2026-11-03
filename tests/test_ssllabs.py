import copy
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import ssllabs as module

METHOD = "get"
KIND = "domain"
VALUE = "example.com"
CONFIG = {"email": "soc@example.com", "allow_scan": True}
PAYLOAD = {
    "host": "example.com",
    "status": "READY",
    "testTime": 1700000000000,
    "endpoints": [
        {
            "ipAddress": "1.1.1.1",
            "statusMessage": "Ready",
            "grade": "A",
            "details": {
                "protocols": [{"name": "TLS", "version": "1.3"}],
                "suites": [{"protocol": 772, "list": [{"name": "TLS_AES_256_GCM_SHA384"}]}],
                "heartbleed": False,
                "poodle": False,
                "poodleTls": -3,
            },
        },
        {"ipAddress": "1.0.0.1", "statusMessage": "Unable to connect", "grade": "A+", "details": {"heartbleed": True}},
    ],
    "certs": [
        {
            "id": "cert1",
            "subject": "CN=example.com",
            "issuerSubject": "CN=Example CA",
            "serialNumber": "1234",
            "sha256Hash": "abababababababababababababababababababababababababababababababab",
            "sha1Hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "notBefore": 1700000000000,
            "notAfter": 1800000000000,
            "altNames": ["example.com", "*.example.com"],
        }
    ],
}

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind=KIND, value=VALUE, config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": dict(CONFIG) if config is None else config,
        }
    )


def response(payload=None, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = payload
    return reply


def handle(payload=None, status=200, **kwargs):
    with patch.object(
        module.requests, METHOD, return_value=response(PAYLOAD if payload is None else payload, status)
    ) as call:
        result = module.handler(query(**kwargs))
    return result, call


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def annotations(result):
    return [json.loads(values(obj)["text"]) for obj in objects(result, "annotation")]


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source metadata"
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(item["to_ids"] is False for item in obj["Attribute"])
        assert obj["template_uuid"]
    assert all(item["to_ids"] is False for item in result["results"]["Attribute"] if item["uuid"] != UUID)


def test_module_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]


@pytest.mark.parametrize(
    "raw", ["{", "[]", "null", "{}", '{"attribute":[]}', '{"attribute":{"type":"ip-dst","value":"1.1.1.1"}}']
)
def test_invalid_request_does_not_call_api(raw):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(raw)
    call.assert_not_called()


@pytest.mark.parametrize("value", ["", "  ", 42, ["example.com"]])
def test_invalid_attribute_value_does_not_call_api(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


def test_unsupported_type_does_not_call_api():
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(kind="comment"))
    call.assert_not_called()


@pytest.mark.parametrize("config", [None, [], "wrong"])
def test_invalid_config_does_not_call_api(config):
    data = json.loads(query())
    data["config"] = config
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(json.dumps(data))
    call.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_http_errors_do_not_leak_credentials(status):
    result, call = handle({"error": SECRET}, status=status)
    assert str(status) in result["error"]
    assert SECRET not in result["error"]
    assert call.call_count == 1
    if status == 429:
        assert "Retry-After" in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_errors_do_not_leak_urls_or_credentials(failure):
    with patch.object(module.requests, METHOD, side_effect=failure("url?key=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


def test_invalid_service_json():
    reply = response()
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, METHOD, return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("payload", [[], "wrong", 1, {}, {"error": SECRET}, {"errors": [{"message": SECRET}]}])
def test_invalid_service_response(payload):
    result, _ = handle(payload)
    assert "error" in result
    assert SECRET not in result["error"]


def test_success_preserves_source_and_disables_ids_on_enrichment():
    result, call = handle()
    assert_source(result)
    assert call.call_count == 1
    assert call.call_args.kwargs["timeout"] == 30
    assert call.call_args.kwargs["allow_redirects"] is False


def test_cache_preference_and_tls_assessment_after_scan_consent():
    result, call = handle()
    assert call.call_args.args[0] == "https://api.ssllabs.com/api/v4/analyze"
    kwargs = call.call_args.kwargs
    assert kwargs["headers"] == {"email": "soc@example.com"}
    assert kwargs["params"] == {"host": VALUE, "publish": "off", "all": "done", "fromCache": "on", "maxAge": 24}
    endpoints = [item for item in annotations(result) if "ip" in item]
    assert endpoints[0]["grade"] == "A"
    assert endpoints[0]["protocols"][0]["version"] == "1.3"
    assert endpoints[0]["heartbleed"] is False
    assert endpoints[0]["poodleTls"] == -3
    assert endpoints[1]["complete"] is False
    assert "grade" not in endpoints[1]
    assert "heartbleed" not in endpoints[1]
    cert = values(objects(result, "x509")[0])
    assert cert["x509-fingerprint-sha256"] == "ab" * 32
    assert "2023-11-14" in cert["validity-not-before"]
    assert len(objects(result, "ip-port")) == 2


@pytest.mark.parametrize("status", ["DNS", "IN_PROGRESS"])
def test_progress_does_not_import_unfinished_grades(status):
    data = dict(PAYLOAD, status=status)
    result, call = handle(data)
    assert_source(result)
    assert len(annotations(result)) == 1
    assert annotations(result)[0]["status"] == status
    assert "again later" in annotations(result)[0]["notice"]
    assert objects(result, "x509") == []
    assert objects(result, "ip-port") == []
    assert call.call_count == 1


@pytest.mark.parametrize("value", [True, "true", "1"])
def test_opt_in_scan_does_not_force_restart_or_publish(value):
    result, call = handle(dict(PAYLOAD, status="IN_PROGRESS"), config=dict(CONFIG, allow_scan=value))
    assert_source(result)
    params = call.call_args.kwargs["params"]
    assert params["fromCache"] == "on"
    assert params["maxAge"] == 24
    assert "startNew" not in params
    assert params["publish"] == "off"
    assert call.call_count == 1


@pytest.mark.parametrize("consent", [None, False, "false", "0", ""])
def test_no_analyze_request_without_explicit_scan_consent(consent):
    config = {"email": CONFIG["email"]}
    if consent is not None:
        config["allow_scan"] = consent
    # Even an apparently cached READY response cannot make analyze safe on a cache miss.
    with patch.object(module.requests, METHOD, return_value=response(PAYLOAD)) as call:
        result = module.handler(query(config=config))
    assert "allow_scan=true" in result["error"]
    call.assert_not_called()


def test_registered_email_is_trimmed_before_authentication():
    result, call = handle(config=dict(CONFIG, email="  soc@example.com\n"))
    assert_source(result)
    assert call.call_args.kwargs["headers"] == {"email": "soc@example.com"}


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"email": "wrong"},
        dict(CONFIG, allow_scan="wrong"),
        dict(CONFIG, max_age=0),
        dict(CONFIG, max_age=721),
        dict(CONFIG, max_age=True),
    ],
)
def test_invalid_config_is_not_sent(config):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(config=config))
    call.assert_not_called()


@pytest.mark.parametrize("value", ["https://example.com", "1.1.1.1", 'example.com"&publish=on', "localhost"])
def test_invalid_hostname_is_not_sent(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


def test_assessment_error_does_not_return_a_grade():
    result, _ = handle(dict(PAYLOAD, status="ERROR", statusMessage=SECRET))
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize(
    "changes",
    [{"host": "other.com"}, {"status": "WRONG"}, {"endpoints": []}, {"endpoints": ["bad"]}, {"certs": ["bad"]}],
)
def test_invalid_assessment_fields(changes):
    result, _ = handle(dict(PAYLOAD, **changes))
    assert "error" in result


def test_certificate_timestamps_also_accept_seconds():
    data = copy.deepcopy(PAYLOAD)
    data["certs"][0]["notBefore"] = 1700000000
    result, _ = handle(data)
    assert "2023-11-14" in values(objects(result, "x509")[0])["validity-not-before"]


def test_idna_hostname_normalization():
    data = dict(PAYLOAD, host="xn--bcher-kva.example")
    result, call = handle(data, value="bücher.example")
    assert_source(result)
    assert call.call_args.kwargs["params"]["host"] == "xn--bcher-kva.example"
