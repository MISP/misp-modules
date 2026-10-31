import base64
import json

from misp_modules.modules.export_mod import defender_endpoint_export

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _export(attributes):
    request = {"data": [{"Attribute": attributes, "Object": []}], "config": {"Period": "7d"}}
    result = defender_endpoint_export.handler(json.dumps(request))
    return base64.b64decode(result["data"]).decode().splitlines()


def test_sha256_query_uses_sha256_columns():
    (query,) = _export([{"type": "sha256", "value": SHA256}])
    assert f"SHA256 == '{SHA256}'" in query
    assert f"InitiatingProcessSHA256 == '{SHA256}'" in query
    assert "SHA1" not in query
