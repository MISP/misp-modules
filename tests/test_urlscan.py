import json
from unittest.mock import patch

from misp_modules.modules.expansion import urlscan

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"

_RESULT = {
    "data": {"requests": [{"response": {}}]},
    "page": {
        "url": "https://circl.lu/team",
        "domain": "circl.lu",
        "ip": "149.13.33.14",
        "ptr": "www.circl.lu",
        "country": "LU",
        "city": "Luxembourg",
        "asn": "AS197692",
        "asnname": "CIRCL",
        "tlsIssuer": "Let's Encrypt",
        "title": "CIRCL team",
        "server": "nginx",
    },
    "stats": {"malicious": 2},
    "meta": {"processors": {"gsb": {"data": {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}}}},
    "lists": {"urls": ["https://circl.lu/office/login"]},
    "task": {
        "url": "https://circl.lu/team",
        "reportURL": "https://urlscan.io/result/abc/",
        "screenshotURL": "https://urlscan.io/screenshots/abc.png",
    },
}


def _run(attribute, result=_RESULT, config=None):
    query = json.dumps(
        {"module": "urlscan", "attribute": attribute, "config": config if config is not None else {"apikey": "k"}}
    )
    with patch.object(urlscan.urlscanAPI, "search_url", return_value=result):
        return urlscan.handler(query)


def _object(result, name):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == name)


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def _attribute(attribute_type="url", value="https://circl.lu/team"):
    return {"type": attribute_type, "value": value, "uuid": UUID}


def test_url_object_holds_the_scanned_url():
    values = _values(_object(_run(_attribute()), "url"))
    assert ("url", "https://circl.lu/team") in values
    assert ("domain", "circl.lu") in values
    assert ("ip", "149.13.33.14") in values
    # title and server both kept, labelled, in the single text relation
    assert ("text", "title: CIRCL team; server: nginx") in values


def test_domain_ip_object_keeps_the_resolution():
    values = _values(_object(_run(_attribute()), "domain-ip"))
    assert ("domain", "circl.lu") in values
    assert ("ip", "149.13.33.14") in values
    assert ("hostname", "www.circl.lu") in values


def test_domain_ip_references_the_url_object():
    result = _run(_attribute())
    url_uuid = _object(result, "url")["uuid"]
    references = _object(result, "domain-ip")["ObjectReference"]
    assert (url_uuid, "resolves-to") in [(r["referenced_uuid"], r["relationship_type"]) for r in references]


def test_geolocation_and_asn_are_their_own_objects():
    result = _run(_attribute())
    assert ("countrycode", "LU") in _values(_object(result, "geolocation"))
    assert ("city", "Luxembourg") in _values(_object(result, "geolocation"))
    asn = _values(_object(result, "asn"))
    assert ("asn", "AS197692") in asn
    assert ("organization", "CIRCL") in asn


def test_tls_issuer_becomes_an_x509_object():
    assert ("issuer", "Let's Encrypt") in _values(_object(_run(_attribute()), "x509"))


def test_screenshot_becomes_an_image_object():
    values = _values(_object(_run(_attribute()), "image"))
    assert ("link", "https://urlscan.io/screenshots/abc.png") in values


def test_verdict_becomes_a_reputation_object():
    values = _values(_object(_run(_attribute()), "reputation"))
    assert ("classification", "malicious") in values
    assert ("source", "urlscan.io") in values
    assert ("score", "2.0") in values
    assert ("link", "https://urlscan.io/result/abc/") in values
    text = next(value for relation, value in values if relation == "text")
    assert "Google Safe Browsing: SOCIAL_ENGINEERING" in text
    assert "possible phishing themes: Office" in text


def test_a_clean_scan_has_no_reputation_object():
    result = dict(_RESULT, stats={}, meta={}, lists={})
    assert _objects(_run(_attribute(), result=result), "reputation") == []


def test_every_object_references_the_input_attribute():
    for misp_object in _run(_attribute())["results"]["Object"]:
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert (UUID, "related-to") in references


def test_unreachable_page_returns_error():
    result = dict(_RESULT, data={"requests": [{"response": {"failed": {"errorText": "net::ERR_NAME_NOT_RESOLVED"}}}]})
    assert "error" in _run(_attribute(), result=result)


def test_ignored_load_errors_do_not_fail_the_scan():
    result = dict(_RESULT, data={"requests": [{"response": {"failed": {"errorText": "net::ERR_ABORTED"}}}]})
    assert "results" in _run(_attribute(), result=result)


def test_missing_api_key_returns_error():
    assert _run(_attribute(), config={})["error"] == "Urlscan apikey is missing"


def test_wrong_attribute_type_returns_error():
    assert "error" in _run(_attribute("md5", "d41d8cd98f00b204e9800998ecf8427e"))


def test_introspection_and_version():
    assert urlscan.introspection() == urlscan.mispattributes
    assert urlscan.mispattributes["format"] == "misp_standard"
    # the module used to declare text/link/hash and then emit an undeclared "AS"
    assert "output" not in urlscan.mispattributes
    assert urlscan.version()["name"] == "URLScan Lookup"
