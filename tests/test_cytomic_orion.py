import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from misp_modules.modules.expansion import cytomic_orion


@pytest.mark.parametrize("first_seen", ["2022-03-14T14:03:21Z", "2022-03-14T15:03:21.123456+01:00"])
@pytest.mark.parametrize("machine_count", [0, 2])
def test_object_first_seen_survives_module_serialization(first_seen, machine_count):
    attribute = {"type": "md5", "value": "a" * 32, "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"}
    config = {
        "api_url": "https://orion.example",
        "token_url": "https://orion.example/token",
        "clientid": "test-client",
        "clientsecret": "test-secret",
        "username": "test-user",
        "password": "test-password",
    }
    file_info = {
        "fileName": "sample.exe",
        "fileSize": 1234,
        "firstSeen": first_seen,
        "lastSeen": "2022-03-16T18:00:00Z",
        "classification": "malware",
        "classificationName": "Example",
    }
    machines = [
        {
            "muid": f"machine-{index}",
            "clientId": "test-client",
            "lastPath": "C:\\sample.exe",
            "firstSeen": f"2022-03-15T10:00:0{index}Z",
            "lastSeen": "2022-03-16T17:00:00Z",
        }
        for index in range(machine_count)
    ]
    machine_info = {
        "machineName": "test-machine",
        "clientName": "test-client",
        "creationDate": "2022-01-01T00:00:00Z",
        "clientCreationDateUTC": "2022-01-01T00:00:00Z",
        "lastSeenUtc": "2022-03-17T00:00:00Z",
    }
    replies = [file_info, machines] + [machine_info] * machine_count
    with (
        patch.object(
            cytomic_orion.requests,
            "post",
            return_value=SimpleNamespace(text=json.dumps({"access_token": "test-token"})),
        ),
        patch.object(
            cytomic_orion.requests, "get", side_effect=[SimpleNamespace(text=json.dumps(reply)) for reply in replies]
        ),
    ):
        result = cytomic_orion.handler(json.dumps({"attribute": attribute, "config": config}))

    objects = result["results"]["Object"]
    assert [obj["name"] for obj in objects] == ["cytomic-orion-file"] + ["cytomic-orion-machine"] * machine_count
    for obj, source in zip(objects, [file_info] + machines):
        values = {item["object_relation"]: item["value"] for item in obj["Attribute"]}
        expected = datetime.fromisoformat(source["firstSeen"].replace("Z", "+00:00"))
        assert datetime.fromisoformat(obj["first_seen"]) == expected
        assert datetime.fromisoformat(values["first-seen"]) == expected
        assert datetime.fromisoformat(values["last-seen"]) == datetime.fromisoformat(
            source["lastSeen"].replace("Z", "+00:00")
        )
