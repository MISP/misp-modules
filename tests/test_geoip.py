import json
from types import SimpleNamespace
from unittest.mock import patch

from misp_modules.modules.expansion import geoip_asn, geoip_city, geoip_country

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
CONFIG = {"local_geolite_db": "/tmp/GeoLite2.mmdb"}


def _named(name):
    return SimpleNamespace(name=name)


_CITY_ANSWER = SimpleNamespace(
    continent=_named("Europe"),
    country=SimpleNamespace(name="Luxembourg", iso_code="LU"),
    subdivisions=SimpleNamespace(most_specific=_named("Luxembourg")),
    city=_named("Luxembourg"),
    postal=SimpleNamespace(code="1855"),
    location=SimpleNamespace(latitude=49.6113, longitude=6.1292, accuracy_radius=5),
)

_COUNTRY_ANSWER = SimpleNamespace(
    continent=_named("Europe"),
    country=SimpleNamespace(name="Luxembourg", iso_code="LU"),
)

_ASN_ANSWER = SimpleNamespace(
    autonomous_system_number=197692,
    autonomous_system_organization="CIRCL",
    network="149.13.33.0/24",
)


def _run(module, attribute, answer, method, config=CONFIG):
    query = json.dumps({"module": module.__name__.split(".")[-1], "attribute": attribute, "config": config})
    with patch.object(module.geoip2.database, "Reader") as mock_reader:
        getattr(mock_reader.return_value, method).return_value = answer
        return module.handler(query)


def _object(result, name):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == name)


def _values(misp_object):
    # pymisp keeps floats as floats and stringifies the rest; compare as strings.
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_city_builds_geolocation_object():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = _run(geoip_city, attribute, _CITY_ANSWER, "city")
    values = _values(_object(result, "geolocation"))
    assert ("country", "Luxembourg") in values
    assert ("countrycode", "LU") in values
    assert ("city", "Luxembourg") in values
    assert ("region", "Luxembourg") in values
    assert ("zipcode", "1855") in values
    assert ("latitude", "49.6113") in values
    assert ("longitude", "6.1292") in values
    assert ("text", "continent: Europe") in values


def test_city_skips_empty_values():
    answer = SimpleNamespace(
        continent=_named(None),
        country=SimpleNamespace(name=None, iso_code="LU"),
        subdivisions=SimpleNamespace(most_specific=_named(None)),
        city=_named(None),
        postal=SimpleNamespace(code=None),
        location=SimpleNamespace(latitude=None, longitude=None, accuracy_radius=None),
    )
    attribute = {"type": "ip-dst", "value": "149.13.33.14", "uuid": UUID}
    result = _run(geoip_city, attribute, answer, "city")
    relations = {relation for relation, _ in _values(_object(result, "geolocation"))}
    assert relations == {"countrycode"}


def test_city_references_the_input_attribute():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = _run(geoip_city, attribute, _CITY_ANSWER, "city")
    references = _object(result, "geolocation")["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]


def test_composite_domain_ip_queries_the_ip():
    attribute = {"type": "domain|ip", "value": "circl.lu|149.13.33.14", "uuid": UUID}
    query = json.dumps({"module": "geoip_city", "attribute": attribute, "config": CONFIG})
    with patch.object(geoip_city.geoip2.database, "Reader") as mock_reader:
        mock_reader.return_value.city.return_value = _CITY_ANSWER
        geoip_city.handler(query)
    assert mock_reader.return_value.city.call_args.args[0] == "149.13.33.14"


def test_country_builds_geolocation_object():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = _run(geoip_country, attribute, _COUNTRY_ANSWER, "country")
    values = _values(_object(result, "geolocation"))
    assert ("countrycode", "LU") in values
    assert ("country", "Luxembourg") in values


def test_asn_builds_asn_object():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = _run(geoip_asn, attribute, _ASN_ANSWER, "asn")
    values = _values(_object(result, "asn"))
    assert ("asn", "AS197692") in values
    assert ("organization", "CIRCL") in values
    assert ("subnet-announced", "149.13.33.0/24") in values


def test_missing_database_path_returns_error():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = geoip_city.handler(json.dumps({"module": "geoip_city", "attribute": attribute, "config": {}}))
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result = _run(geoip_city, attribute, _CITY_ANSWER, "city")
    assert "error" in result


def test_introspection_and_version():
    for module in (geoip_city, geoip_country, geoip_asn):
        assert module.introspection() == module.mispattributes
        assert module.mispattributes["format"] == "misp_standard"
        assert "config" in module.version()
