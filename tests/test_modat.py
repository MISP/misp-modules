"""Offline contract tests for MODAT; no API credentials or module server required."""

import base64
import json
from unittest.mock import Mock, patch

import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import modat

UUID = "12345678-1234-4234-8234-123456789012"


def attribute(typ="ip-dst", value="203.0.113.14"):
    return {"type": typ, "value": value, "uuid": UUID}


def request(typ="ip-dst", value="203.0.113.14", **config):
    return json.dumps(
        {"attribute": attribute(typ, value), "config": {"apikey": "test-secret", "reverse_dns": False, **config}}
    )


def response(data, status=200, headers=None):
    result = Mock(status_code=status, headers=headers or {})
    result.json.return_value = data
    return result


VALID = {
    "AS": "AS64496",
    "domain": "example.com",
    "hostname": "example.com",
    "port": "443",
    "x509-fingerprint-sha1": "a" * 40,
    "x509-fingerprint-sha256": "a" * 64,
    "jarm-fingerprint": "a" * 62,
    "hasshserver-md5": "a" * 32,
    "ssh-fingerprint": "a" * 64,
    "favicon-mmh3": "-1234",
    "vulnerability": "CVE-2023-44487",
    "sha1": "a" * 40,
    "sha256": "a" * 64,
    "email": "admin@example.com",
    "email-src": "admin@example.com",
    "email-dst": "admin@example.com",
    "target-email": "admin@example.com",
    "target-org": "Example Org",
    "ip-src": "203.0.113.14",
    "ip-dst": "2001:db8::1",
    "ip-src|port": "2001:db8::1|443",
    "ip-dst|port": "203.0.113.14|443",
    "domain|ip": "example.com|203.0.113.14",
    "hostname|port": "example.com|443",
    "url": "https://example.com/path",
    "uri": "http://[2001:db8::1]:8080/x",
    "link": "https://example.com/",
    "filename|sha1": "favicon.ico|" + "a" * 40,
    "filename|sha256": "favicon.ico|" + "a" * 64,
    "text": "Example Webserver",
    "hex": "0001ab",
    "pattern-in-traffic": "OpenSSH",
}


@pytest.mark.parametrize("typ,value", VALID.items())
def test_supported_inputs(typ, value):
    assert typ in modat.introspection()["input"]
    ip, query, zone = modat.build_query(attribute(typ, value))
    assert ip or query
    assert query is None or len(query) <= 2000


def test_every_advertised_type_has_a_valid_case():
    assert set(VALID) == set(modat.introspection()["input"])


@pytest.mark.parametrize(
    "typ,value",
    [
        ("md5", "a" * 32),
        ("ja3-fingerprint-md5", "a" * 32),
        ("hassh-md5", "a" * 32),
        ("x509-fingerprint-md5", "a" * 32),
        ("ip-dst|port", "203.0.113.1|70000"),
        ("ip-dst|port", "1.2.3.4|80|443"),
        ("domain|ip", "evil.invalid|not-an-ip"),
        ("domain", 'x" OR port=22'),
        ("text", 'x" OR port=22'),
        ("text", "x\\y"),
        ("text", "hello\nworld"),
        ("url", "file:///etc/passwd"),
        ("uri", "relative/path"),
        ("url", "https://user:pass@example.com"),
        ("sha256", "abc"),
        ("ssh-fingerprint", "SHA256:abc"),
        ("AS", "AS-1"),
        ("favicon-mmh3", "999999999999"),
        ("vulnerability", "not-a-cve"),
    ],
)
def test_invalid_inputs(typ, value):
    with pytest.raises(ValueError):
        modat.build_query(attribute(typ, value))


def test_composite_constraints_and_network():
    assert modat.build_query(attribute("ip-dst|port", "2001:db8::1|8443"))[1] == 'ip="2001:db8::1" AND port=8443'
    assert (
        modat.build_query(attribute("domain|ip", "example.com|203.0.113.1"))[1]
        == 'fqdns="example.com" AND ip="203.0.113.1"'
    )
    assert modat.build_query(attribute("ip-src", "203.0.113.1/24"))[1] == 'subnet="203.0.113.0/24"'
    assert modat.build_query(attribute("domain", "example[.]com"))[2] == "example.com"
    assert modat.build_query(attribute("domain", "bücher.example"))[2] == "xn--bcher-kva.example"


def test_search_pagination_and_bound():
    client = modat.ModatClient("secret", 5)
    client.session.request = Mock(
        side_effect=[
            response({"page": [{"n": i} for i in range(10)], "total_pages": 20}),
            response({"page": [{"n": i} for i in range(10, 20)], "total_pages": 20}),
        ]
    )
    rows = client.search("/service/search/v1", "port=443", 12, 10)
    assert len(rows) == 12
    assert client.session.request.call_count == 2
    args = client.session.request.call_args.kwargs
    assert args["json"]["page"] == 2
    assert args["timeout"] == 5
    assert args["allow_redirects"] is False
    client.session.close()


@pytest.mark.parametrize(
    "status,message",
    [
        (401, "authentication"),
        (403, "subscription"),
        (429, "Retry after 7"),
        (422, "HTTP 422"),
        (500, "HTTP 500"),
        (302, "HTTP 302"),
    ],
)
def test_errors_are_sanitized(status, message):
    with patch.object(
        modat.requests.Session,
        "request",
        return_value=response({"secret": "test-secret"}, status, {"Retry-After": "7"}),
    ):
        result = modat.handler(request())
    assert message in result["error"]
    assert "test-secret" not in result["error"]


def test_invalid_requests_and_network_failures():
    assert modat.handler(False) is False
    for raw in ("bad JSON", "[]", "{}", json.dumps({"attribute": attribute(), "config": {}})):
        assert "error" in modat.handler(raw)
    with patch.object(modat.requests.Session, "request", side_effect=modat.requests.Timeout("test-secret")):
        assert "test-secret" not in modat.handler(request())["error"]


@pytest.mark.parametrize(
    "config",
    [{"page_size": 9}, {"max_results": 1001}, {"timeout": 0}, {"include_dns": "maybe"}, {"max_results": False}],
)
def test_invalid_config(config):
    with patch.object(modat.requests.Session, "request") as call:
        assert "error" in modat.handler(request(**config))
        call.assert_not_called()


def service():
    return {
        "transport": "tcp",
        "ports": [443, 8443],
        "last_scanned_port": 443,
        "protocol": "http",
        "scanned_at": "2026-10-01T08:15:42Z",
        "discovered_at": "2026-01-01T00:00:00Z",
        "banner_mmh3": 0,
        "tcp": {"window_size": 0},
        "tls": {
            "fingerprint_sha256": "a" * 64,
            "is_self_signed": False,
            "is_trusted": True,
            "subject": {"common_name": ["example.com"]},
            "extensions": {"subject_alt_name": {"dns": ["example.com"], "ipv6": ["2001:db8::1"]}},
        },
        "ssh": {"hassh": "b" * 32, "key_exchange": {"server_host_key": {"fingerprint_sha256": "c" * 64}}},
        "http": {
            "status_code": 200,
            "body_sha256": "d" * 64,
            "files": [
                {"path": "favicon.ico", "category": "favicon", "sha256": "e" * 64, "mmh3": 0},
                {"path": "other.ico", "category": "favicon", "sha256": "f" * 64, "mmh3": 42},
            ],
        },
        "fingerprints": {"service": {"product": "nginx", "version": "1.24.0"}, "tags": ["Cloud"]},
        "cves": [{"id": "CVE-2023-44487", "cvss": 0.0, "is_kev": False}],
        "future_field": {"nested": "preserve-me"},
    }


def test_objects_references_and_original_data():
    parser = modat.ModatParser(attribute())
    host = {
        "ip": "203.0.113.14",
        "asn": {"number": 64496, "org": "Example", "netblock": "203.0.113.0/24"},
        "geo": {"location": [-118.24, 34.05], "country_iso_code": "US"},
        "is_anycast": False,
        "fqdns": ["example.com"],
        "services": [service(), service()],
    }
    parser.host(host)
    result = parser.result()["results"]
    names = [o["name"] for o in result["Object"]]
    assert names.count("modat-service") == 1
    assert names.count("file") == 2
    assert set(("ip-port", "asn", "geolocation", "x509", "vulnerability", "software")) <= set(names)
    custom = next(o for o in result["Object"] if o["name"] == "modat-service")
    attrs = {a["object_relation"]: a for a in custom["Attribute"]}
    assert attrs["tls-is-self-signed"]["value"] is False
    assert str(attrs["banner-mmh3"]["value"]) == "0"
    raw = json.loads(base64.b64decode(attrs["raw-json"]["data"]))
    assert raw == service()
    geo = next(o for o in result["Object"] if o["name"] == "geolocation")
    coords = {
        a["object_relation"]: float(a["value"])
        for a in geo["Attribute"]
        if a["object_relation"] in ("latitude", "longitude")
    }
    assert coords["longitude"] == -118.24 and coords["latitude"] == 34.05
    ids = {a["uuid"] for a in result["Attribute"]} | {o["uuid"] for o in result["Object"]}
    for obj in result["Object"]:
        for ref in obj.get("ObjectReference", []):
            assert ref["referenced_uuid"] in ids
        for a in obj["Attribute"]:
            assert a["to_ids"] is False
        loaded = MISPObject(
            obj["name"],
            strict=True,
            misp_objects_path_custom=modat.DATA_PATH if obj["name"].startswith("modat-") else None,
        )
        loaded.from_dict(**obj)
        loaded._validate()
    assert len(result["Attribute"]) == 2  # input and raw host evidence


def test_dns_history_and_https_root_target():
    parser = modat.ModatParser(attribute("domain", "example.com"))
    zone = {
        "fqdn": "example.com",
        "records": {
            "a": [
                {
                    "ttl": 0,
                    "created_at": "2025-01-01T00:00:00Z",
                    "deleted_at": "2026-01-01T00:00:00Z",
                    "ip": "203.0.113.14",
                }
            ],
            "https": [
                {"ttl": 3600, "created_at": "2025-01-01T00:00:00Z", "priority": 1, "target": ".", "params": 'alpn="h2"'}
            ],
            "soa": [
                {
                    "ttl": 3600,
                    "created_at": "2025-01-01T00:00:00Z",
                    "mname": "ns.example.com.",
                    "rname": "hostmaster.example.com.",
                    "serial": 1,
                    "refresh": 2,
                    "retry": 3,
                    "expire": 4,
                    "minimum": 0,
                }
            ],
        },
    }
    parser.dns(zone)
    parser.dns(zone)
    objects = parser.result()["results"]["Object"]
    observations = [o for o in objects if o["name"] == "modat-dns-record"]
    assert len(observations) == 3
    https = next(o for o in observations if any(a["value"] == "HTTPS" for a in o["Attribute"]))
    assert next(a["value"] for a in https["Attribute"] if a["object_relation"] == "target") == "."
    domain_ip = next(o for o in objects if o["name"] == "domain-ip")
    assert not any(a["object_relation"] == "last-seen" for a in domain_ip["Attribute"])
    for obj in parser.event.objects:
        obj._validate()


def test_direct_lookup_missing_and_dns_success():
    zone = {
        "fqdn": "example.com",
        "records": {"txt": [{"ttl": 0, "created_at": "2026-01-01T00:00:00Z", "value": "v=spf1 -all"}]},
    }
    with patch.object(
        modat.requests.Session, "request", side_effect=[response({"page": [], "total_pages": 0}), response(zone)]
    ) as call:
        result = modat.handler(request("domain", "example.com"))
    assert "error" not in result
    assert any(o["name"] == "modat-dns-record" for o in result["results"]["Object"])
    assert call.call_count == 2
    with patch.object(modat.requests.Session, "request", return_value=response({}, 404)):
        result = modat.handler(request())
    assert result["results"]["Object"] == []


def test_reverse_dns_lookup():
    zone = {"fqdn": "example.com", "records": {}}
    with patch.object(
        modat.requests.Session,
        "request",
        side_effect=[
            response({}, 404),
            response({"page": [{"fqdn": "example.com"}], "total_pages": 1}),
            response(zone),
        ],
    ) as call:
        result = modat.handler(request(reverse_dns=True))
    assert "error" not in result
    assert call.call_args_list[1].kwargs["json"]["query"] == 'a.ip="203.0.113.14"'


@pytest.mark.parametrize(
    "data", [{"page": []}, {"page": "bad", "total_pages": 1}, {"errors": ["bad query"]}, {"data": []}]
)
def test_malformed_api_responses(data):
    with patch.object(modat.requests.Session, "request", return_value=response(data)):
        assert "error" in modat.handler(request("sha256", "a" * 64))


def test_pinned_openapi_service_schema_is_fully_mapped():
    """Detect dropped fields, invalid attribute types and template drift against the vendor contract."""
    from pathlib import Path

    spec = json.loads((Path(__file__).parent / "test_files" / "modat_openapi.json").read_text())
    schemas = spec["components"]["schemas"]
    paths = set()

    def sample(schema, path=""):
        if "$ref" in schema:
            return sample(schemas[schema["$ref"].split("/")[-1]], path)
        if "anyOf" in schema:
            return sample(next(item for item in schema["anyOf"] if item.get("type") != "null"), path)
        if "properties" in schema:
            return {key: sample(value, f"{path}.{key}" if path else key) for key, value in schema["properties"].items()}
        if schema.get("type") == "array":
            return [sample(schema["items"], path)]
        paths.add(path)
        if schema.get("format") == "date-time":
            return "2026-01-01T00:00:00Z"
        if schema.get("enum"):
            return schema["enum"][0]
        if path.endswith(("sha1", "sha256")):
            return "a" * (40 if path.endswith("sha1") else 64)
        if path.endswith(("ipv4", "ipv6")):
            return "2001:db8::1" if path.endswith("ipv6") else "203.0.113.1"
        if path.endswith(".dns"):
            return "example.com"
        if path.endswith((".email", ".email_address")):
            return "admin@example.com"
        if path.endswith(".uri") or path.endswith("icon_url"):
            return "https://example.com/"
        if path in ("port", "ports", "last_scanned_port"):
            return 443
        if path == "ssh.hassh":
            return "b" * 32
        if path == "tls.jarm":
            return "c" * 62
        return {"boolean": False, "integer": 0, "number": 0.0}.get(schema.get("type"), "example")

    data = sample(schemas["_DetailedService"])
    assert paths == set(modat.SERVICE_MAPPING)
    parser = modat.ModatParser(attribute())
    parser.host(
        {
            "ip": "203.0.113.14",
            "services": [data],
            "is_anycast": False,
            "tags": ["Cloud", "Security Tool"],
            "fqdns": ["one.example.com", "two.example.com"],
            "rdns": ["one.example.com", "two.example.com"],
            "asn": {"number": 64496, "org": "Example", "netblock": "203.0.113.0/24"},
            "geo": {
                "country_name": "Luxembourg",
                "country_iso_code": "LU",
                "city_name": "Luxembourg",
                "accuracy_radius": 1,
                "location": [6.13, 49.61],
            },
        }
    )
    service_object = next(o for o in parser.event.objects if o.name == "modat-service")
    assert {a.object_relation for a in service_object.attributes} == {
        path.replace(".", "-").replace("_", "-") for path in paths
    } | {"ip", "raw-json"}
    known_types = set(parser.source.describe_types["types"])
    for obj in parser.event.objects:
        obj._validate()
        for a in obj.attributes:
            assert a.type in known_types


def test_object_templates_conform_to_misp_schema():
    from pathlib import Path

    import jsonschema
    import pymisp

    schema = json.loads((Path(pymisp.__file__).parent / "data/misp-objects/schema_objects.json").read_text())
    for file in modat.DATA_PATH.glob("*/definition.json"):
        jsonschema.Draft4Validator(schema).validate(json.loads(file.read_text()))


def test_search_single_port_and_incomplete_geo():
    row = {
        "ip": "203.0.113.14",
        "geo": {"accuracy_radius": 1},
        "service": {"port": 8443, "transport": "tcp", "protocol": "http", "scanned_at": "2026-01-01T00:00:00Z"},
    }
    with patch.object(modat.requests.Session, "request", return_value=response({"page": [row], "total_pages": 1})):
        result = modat.handler(request("port", "8443"))
    assert "error" not in result
    observations = [o for o in result["results"]["Object"] if o["name"] == "modat-service"]
    assert len(observations) == 1
    assert any(a["object_relation"] == "ports" and str(a["value"]) == "8443" for a in observations[0]["Attribute"])
    assert not any(o["name"] == "geolocation" for o in result["results"]["Object"])


@pytest.mark.parametrize("source_uuid", [UUID, "abcdefab-1234-4234-8234-abcdefabcdef"])
def test_identical_evidence_has_distinct_ids_across_enrichments(source_uuid):
    host = {"ip": "203.0.113.14", "asn": {"number": 64496}, "services": [service()]}
    zone = {
        "fqdn": "example.com",
        "records": {"a": [{"ip": "203.0.113.14", "ttl": 300, "created_at": "2026-01-01T00:00:00Z"}]},
    }
    results = []
    for uuid in (UUID, source_uuid):
        source = {**attribute(), "uuid": uuid}
        parser = modat.ModatParser(source)
        parser.host(host)
        parser.dns(zone)
        results.append(parser.result()["results"])

    def generated_ids(result, source_id):
        return (
            {o["uuid"] for o in result["Object"]}
            | {a["uuid"] for o in result["Object"] for a in o["Attribute"]}
            | {a["uuid"] for a in result["Attribute"] if a["uuid"] != source_id}
        )

    first_ids = generated_ids(results[0], UUID)
    second_ids = generated_ids(results[1], source_uuid)
    assert first_ids.isdisjoint(second_ids)
    for result, source_id in zip(results, (UUID, source_uuid)):
        local_ids = generated_ids(result, source_id) | {source_id}
        assert any(a["type"] == "attachment" for a in result["Attribute"])
        for obj in result["Object"]:
            for ref in obj.get("ObjectReference", []):
                assert ref["referenced_uuid"] in local_ids


def test_duplicate_host_evidence_is_reused_within_response():
    parser = modat.ModatParser(attribute())
    host = {"ip": "203.0.113.14", "services": [service()]}
    parser.host(host)
    first = parser.result()["results"]
    parser.host(host)
    second = parser.result()["results"]
    assert {o["uuid"] for o in first["Object"]} == {o["uuid"] for o in second["Object"]}
    attachments = [a for a in second["Attribute"] if a["type"] == "attachment"]
    assert len(attachments) == 1
    for obj in second["Object"]:
        refs = [(r["referenced_uuid"], r["relationship_type"]) for r in obj.get("ObjectReference", [])]
        assert len(refs) == len(set(refs))


def test_multiple_reverse_dns_names_use_dns_record():
    host = {"ip": "203.0.113.14", "rdns": ["one.example.com", "two.example.com"], "services": []}
    with patch.object(modat.requests.Session, "request", return_value=response({"data": host})):
        result = modat.handler(request("ip-src", host["ip"], include_dns=False))
    assert "error" not in result
    objects = result["results"]["Object"]
    dns = next(o for o in objects if o["name"] == "dns-record")
    assert {a["value"] for a in dns["Attribute"] if a["object_relation"] == "ptr-record"} == set(host["rdns"])
    assert (
        next(a["value"] for a in dns["Attribute"] if a["object_relation"] == "queried-domain")
        == "14.113.0.203.in-addr.arpa"
    )
    endpoint = next(o for o in objects if o["name"] == "ip-port")
    assert len([a for a in endpoint["Attribute"] if a["object_relation"] == "ptr-record"]) <= 1


def test_certificate_multiple_distinguished_name_values_are_preserved():
    observed = service()
    observed["tls"]["issuer"] = {"common_name": ["Issuer One", "Issuer Two"], "organization": ["Org One", "Org Two"]}
    observed["tls"]["subject"] = {"common_name": ["one.example.com", "two.example.com"], "country": ["LU", "BE"]}
    host = {"ip": "203.0.113.14", "services": [observed]}
    with patch.object(modat.requests.Session, "request", return_value=response({"data": host})):
        result = modat.handler(request("ip-src", host["ip"], include_dns=False))
    assert "error" not in result
    cert = next(o for o in result["results"]["Object"] if o["name"] == "x509")
    values = {a["object_relation"]: a["value"] for a in cert["Attribute"]}
    assert "CN=Issuer One,CN=Issuer Two" in values["issuer"]
    assert "O=Org One,O=Org Two" in values["issuer"]
    assert "CN=one.example.com,CN=two.example.com" in values["subject"]
    assert "C=LU,C=BE" in values["subject"]
    for rel in ("issuer-common-name", "issuer-organization", "subject-common-name", "subject-country"):
        assert len([a for a in cert["Attribute"] if a["object_relation"] == rel]) <= 1


def test_full_misp_request_with_reverse_dns_and_multiple_rdn_values():
    source = {
        **attribute("ip-src"),
        "id": "1",
        "event_id": "2",
        "category": "Network activity",
        "value1": "203.0.113.14",
        "value2": "",
        "to_ids": False,
        "timestamp": "1791885325",
        "distribution": "0",
        "comment": "",
        "sharing_group_id": "0",
        "deleted": False,
        "disable_correlation": False,
        "object_id": "0",
        "object_relation": None,
        "first_seen": None,
        "last_seen": None,
    }
    observed = service()
    observed["tls"]["subject"]["common_name"] = ["one.example.com", "two.example.com"]
    host = {"ip": source["value"], "rdns": ["one.example.com", "two.example.com"], "services": [observed]}
    zone = {
        "fqdn": "example.com",
        "records": {"a": [{"ip": source["value"], "ttl": 300, "created_at": "2026-01-01T00:00:00Z"}]},
    }
    q = json.dumps(
        {
            "module": "modat",
            "attribute": source,
            "event_id": "2",
            "timeout": 10,
            "config": {
                "apikey": "test-secret",
                "max_results": "1",
                "page_size": "10",
                "timeout": "10",
                "include_dns": "1",
                "reverse_dns": "1",
            },
        }
    )
    with patch.object(
        modat.requests.Session,
        "request",
        side_effect=[
            response({"data": host}),
            response({"page": [{"fqdn": "example.com"}], "total_pages": 1}),
            response(zone),
        ],
    ) as call:
        result = modat.handler(q)
    assert "error" not in result
    assert call.call_count == 3
    assert {"modat-service", "x509", "dns-record", "modat-dns-record", "domain-ip"} <= {
        o["name"] for o in result["results"]["Object"]
    }
    assert result["results"]["Attribute"][0]["uuid"] == source["uuid"]


@pytest.mark.parametrize("method,stage", [("host", "MODAT host data"), ("result", "MISP enrichment output")])
def test_parser_errors_identify_stage_without_leaking_data(method, stage, caplog):
    with (
        patch.object(
            modat.requests.Session, "request", return_value=response({"data": {"ip": "203.0.113.14", "services": []}})
        ),
        patch.object(modat.ModatParser, method, side_effect=TypeError("test-secret private response")),
    ):
        result = modat.handler(request(include_dns=False))
    assert result["error"] == f"Unable to process {stage} (TypeError)."
    assert stage in caplog.text
    assert "test-secret" not in result["error"] + caplog.text
    assert "private response" not in result["error"] + caplog.text


@pytest.mark.parametrize(
    "anycast,tags", [(False, ["Cloud"]), (True, ["Cloud", "Security Tool"]), (None, ["Cloud", "Security Tool"])]
)
def test_host_classification_notes_respect_single_value_relation(anycast, tags):
    host = {"ip": "203.0.113.14", "tags": tags, "services": []}
    if anycast is not None:
        host["is_anycast"] = anycast
    with patch.object(modat.requests.Session, "request", return_value=response({"data": host})):
        result = modat.handler(request(include_dns=False))
    assert "error" not in result
    endpoint = next(o for o in result["results"]["Object"] if o["name"] == "ip-port")
    notes = [a["value"] for a in endpoint["Attribute"] if a["object_relation"] == "text"]
    assert len(notes) == 1
    for tag in tags:
        assert f"MODAT classification: {tag}" in notes[0]
    if anycast is not None:
        assert f"MODAT is_anycast={str(anycast).lower()}" in notes[0]
    evidence = next(a for a in result["results"]["Attribute"] if a["type"] == "attachment")
    assert json.loads(base64.b64decode(evidence["data"])) == host


@pytest.mark.parametrize("missing", [False, True])
def test_object_validation_diagnostics_identify_constraints_without_values(missing, caplog):
    parser = modat.ModatParser(attribute())
    if missing:
        obj = MISPObject("dns-record", strict=True)
        parser.add(obj, "txt-record", "private-response-one")
        expected = "Cannot validate MISP object 'dns-record': required relations missing: queried-domain."
    else:
        obj = MISPObject("ip-port", strict=True)
        parser.add(obj, "ip", "203.0.113.14")
        parser.add(obj, "text", "private-response-one")
        parser.add(obj, "text", "private-response-two")
        expected = "Cannot validate MISP object 'ip-port': single-valued relations repeated: text."
    with pytest.raises(modat.ModatError) as error:
        parser.put(obj)
    assert str(error.value) == expected
    assert expected in caplog.text
    assert "private-response" not in str(error.value) + caplog.text


@pytest.mark.parametrize("unset", ["missing", None, "", "  \t "])
def test_optional_settings_use_screenshot_defaults_when_unset(unset):
    config = {"apikey": "test-secret"}
    if unset != "missing":
        config.update({key: unset for key in modat.DEFAULT_CONFIG})
    q = json.dumps({"attribute": attribute(), "config": config})
    host = {"data": {"ip": "203.0.113.14", "services": []}}
    rows = {"page": [{"fqdn": "first.example.com"}, {"fqdn": "second.example.com"}], "total_pages": 2}
    with patch.object(
        modat.requests.Session,
        "request",
        side_effect=[response(host), response(rows), response({"fqdn": "first.example.com", "records": {}})],
    ) as call:
        result = modat.handler(q)
    assert "error" not in result
    assert call.call_count == 3  # Both DNS options enabled, max_results limits zone lookups to one.
    assert all(c.kwargs["timeout"] == 10 for c in call.call_args_list)
    assert call.call_args_list[1].kwargs["json"]["page_size"] == 10
    assert call.call_args_list[2].args[1].endswith("/dns/zones/first.example.com/v1")
    assert result["results"]["Object"]


def test_optional_setting_overrides_are_preserved():
    config = {
        "max_results": " 3 ",
        "page_size": " 20 ",
        "timeout": " 45 ",
        "include_dns": " false ",
        "reverse_dns": False,
    }
    assert modat._integer(config, "max_results", 1, 1, 1000) == 3
    assert modat._integer(config, "page_size", 10, 10, 100) == 20
    assert modat._integer(config, "timeout", 10, 1, 120) == 45
    assert modat._boolean(config, "include_dns", True) is False
    assert modat._boolean(config, "reverse_dns", True) is False
    assert modat._boolean({"reverse_dns": 0}, "reverse_dns", True) is False


@pytest.mark.parametrize("key", [None, "", "   "])
def test_api_key_remains_required_with_optional_defaults(key):
    with patch.object(modat.requests.Session, "request") as call:
        result = modat.handler(json.dumps({"attribute": attribute(), "config": {"apikey": key}}))
    assert "API key" in result["error"]
    call.assert_not_called()
