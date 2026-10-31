import base64
import json

import yara

from misp_modules.modules.export_mod import yara_export


def _export(attributes):
    event = {
        "Event": {"id": "1", "info": "Test event", "date": "2026-10-27", "uuid": "uuid"},
        "Orgc": {"name": "ORG"},
        "Attribute": attributes,
    }
    result = yara_export.handler(json.dumps({"data": [event]}))
    return base64.b64decode(result["data"]).decode()


def test_combined_attribute():
    output = _export(
        [
            {"type": "filename|md5", "to_ids": True, "value": "evil.exe|d41d8cd98f00b204e9800998ecf8427e"},
            {"type": "ip-dst|port", "to_ids": True, "value": "192.0.2.1|443"},
        ]
    )
    yara.compile(source=output)
    assert '$filename_0 = "evil.exe"' in output
    assert '$ip_dst_0 = "192.0.2.1"' in output


def test_malware_sample():
    output = _export(
        [{"type": "malware-sample", "to_ids": True, "value": "sample.bin|d41d8cd98f00b204e9800998ecf8427e"}]
    )
    yara.compile(source=output)
    assert '$filename_0 = "sample.bin"' in output


def test_combined_attribute_not_to_ids():
    output = _export([{"type": "filename|md5", "to_ids": False, "value": "evil.exe|d41d8cd98f00b204e9800998ecf8427e"}])
    assert "evil.exe" not in output
