import json
from unittest.mock import MagicMock, patch

from misp_modules.modules.expansion import vulners

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
CVE = "CVE-2010-3333"

_DOCUMENT = {
    "id": CVE,
    "title": "Microsoft Office RTF Stack Buffer Overflow Vulnerability",
    "description": '"RTF Stack Buffer Overflow Vulnerability."',
    "published": "2010-11-10T00:00:00",
    "modified": "2018-10-12T00:00:00",
    "cvss": {"score": 9.3, "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
    "references": ["https://vulners.com/cve/CVE-2010-3333"],
    "enchantments": {"score": {"value": 8.4}},
}

_EXPLOITS = [
    {
        "title": "Microsoft Office RTF parsing overflow",
        "href": "https://vulners.com/exploitdb/EDB-ID:17474",
        "description": "Metasploit module",
        "sourceData": "## exploit source ##",
    },
    {"title": "MS Office RTF PoC", "href": "https://vulners.com/packetstorm/PACKETSTORM:106186"},
]


def _run(attribute, document=_DOCUMENT, exploits=_EXPLOITS, config=None):
    query = json.dumps(
        {"module": "vulners", "attribute": attribute, "config": config if config is not None else {"apikey": "x"}}
    )
    with patch.object(vulners, "vulners") as mock_vulners:
        api = MagicMock()
        api.document.return_value = document
        api.searchExploit.return_value = exploits
        mock_vulners.Vulners.return_value = api
        return vulners.handler(query)


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_vulnerability_object_carries_the_document():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    values = _values(_objects(_run(attribute), "vulnerability")[0])
    assert ("id", CVE) in values
    assert ("description", '"RTF Stack Buffer Overflow Vulnerability."') in values
    assert ("cvss-score", "9.3") in values
    assert ("cvss-string", "AV:N/AC:M/Au:N/C:C/I:C/A:C") in values
    assert ("references", "https://vulners.com/cve/CVE-2010-3333") in values


def test_one_exploit_object_per_exploit():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    exploits = _objects(_run(attribute), "exploit")
    assert len(exploits) == 2
    titles = {value for obj in exploits for relation, value in _values(obj) if relation == "title"}
    assert titles == {"Microsoft Office RTF parsing overflow", "MS Office RTF PoC"}
    assert ("cve-id", CVE) in _values(exploits[0])
    assert ("exploit", "## exploit source ##") in _values(exploits[0])
    # no sourceData on the second one: title and reference satisfy the template
    # on their own from exploit v2, so nothing is invented for it
    assert "exploit" not in {relation for relation, _ in _values(exploits[1])}
    assert ("reference", "https://vulners.com/packetstorm/PACKETSTORM:106186") in _values(exploits[1])


def test_ai_score_goes_to_a_reputation_object():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    values = _values(_objects(_run(attribute), "reputation")[0])
    assert ("source", "Vulners") in values
    assert ("score", "8.4") in values


def test_every_object_references_the_input_attribute():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    for misp_object in _run(attribute)["results"]["Object"]:
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert references == [(UUID, "related-to")]


def test_no_exploits_still_returns_the_vulnerability():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    result = _run(attribute, exploits=[])
    assert len(_objects(result, "vulnerability")) == 1
    assert _objects(result, "exploit") == []


def test_unknown_cve_returns_error():
    attribute = {"type": "vulnerability", "value": "CVE-1999-0000", "uuid": UUID}
    assert "error" in _run(attribute, document={})


def test_missing_api_key_returns_error():
    attribute = {"type": "vulnerability", "value": CVE, "uuid": UUID}
    result = _run(attribute, config={})
    assert result["error"] == "A Vulners api key is required for this module."


def test_introspection_and_version():
    assert vulners.introspection() == vulners.mispattributes
    assert vulners.mispattributes["format"] == "misp_standard"
    assert vulners.version()["name"] == "Vulners Lookup"
