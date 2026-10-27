import base64
import csv
import io
import json

from misp_modules.modules.export_mod import threat_connect_export


def _export(attributes):
    event = {"Event": {"id": "1", "info": "Test event"}, "Attribute": attributes}
    result = threat_connect_export.handler(json.dumps({"data": [event], "config": {"Default_Source": "MISP"}}))
    rows = csv.DictReader(io.StringIO(base64.b64decode(result["data"]).decode()))
    return [(row["Type"], row["Value"]) for row in rows]


def test_composite_attributes():
    rows = _export(
        [
            {"type": "ip-dst|port", "value": "192.0.2.1|443", "comment": ""},
            {"type": "ip-src|port", "value": "2001:db8::1|8080", "comment": ""},
            {"type": "filename|md5", "value": "evil.exe|d41d8cd98f00b204e9800998ecf8427e", "comment": ""},
            {"type": "domain|ip", "value": "example.com|192.0.2.2", "comment": ""},
        ]
    )
    assert rows == [
        ("Address", "192.0.2.1"),
        ("Address", "2001:db8::1"),
        ("File", "d41d8cd98f00b204e9800998ecf8427e"),
        ("Host", "example.com"),
        ("Address", "192.0.2.2"),
    ]


def test_single_attributes():
    rows = _export(
        [
            {"type": "domain", "value": "example.com", "comment": ""},
            {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "comment": ""},
        ]
    )
    assert rows == [("Host", "example.com"), ("File", "d41d8cd98f00b204e9800998ecf8427e")]
