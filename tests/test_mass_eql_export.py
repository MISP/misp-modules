import base64
import json

from misp_modules.modules.export_mod import mass_eql_export


def _export(attributes):
    result = mass_eql_export.handler(json.dumps({"data": [{"Attribute": attributes}]}))
    return base64.b64decode(result["data"]).decode()


def test_each_event_type_is_a_separate_query():
    output = _export(
        [
            {"type": "ip-src", "value": "10.0.0.1"},
            {"type": "ip-dst", "value": "10.0.0.2"},
            {"type": "filename", "value": "a.exe"},
            {"type": "filename", "value": "b.exe"},
        ]
    )
    assert (
        output
        == 'network where\n\tsource_address == "10.0.0.1" or\n\tdestination_address == "10.0.0.2"\n'
        "\n"
        'file where\n\tfile_name == "a.exe" or\n\tfile_name == "b.exe"\n'
    )


def test_values_are_escaped():
    output = _export(
        [
            {"type": "filename", "value": "C:\\Windows\\Temp\\x.exe"},
            {"type": "filename", "value": 'a"b.txt'},
        ]
    )
    assert output == 'file where\n\tfile_name == "C:\\\\Windows\\\\Temp\\\\x.exe" or\n\tfile_name == "a\\"b.txt"\n'


def test_no_supported_attribute():
    assert _export([{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}]) == ""
