import base64
import json
from pathlib import Path

from misp_modules.modules.import_mod import darkmoon_import

FIXTURE = Path(__file__).parent / "darkmoon_findings.json"


def _request(data, **config):
    return json.dumps({"data": base64.b64encode(data).decode(), "config": config})


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(obj, relation):
    return [attribute["value"] for attribute in obj["Attribute"] if attribute["object_relation"] == relation]


def test_import_findings():
    result = darkmoon_import.handler(_request(FIXTURE.read_bytes()))
    vulnerabilities = _objects(result, "vulnerability")
    urls = _objects(result, "url")
    assert len(vulnerabilities) == 3
    assert len(urls) == 3

    rce = vulnerabilities[0]
    assert _values(rce, "summary") == ["Unauthenticated remote code execution in file upload handler"]
    assert _values(rce, "id") == ["CVE-2026-12345"]
    assert _values(rce, "cvss-score") == ["9.8"]
    assert _values(rce, "cvss-string") == ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
    assert _values(rce, "references") == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        "https://attack.mitre.org/techniques/T1190/",
    ]
    description = _values(rce, "description")[0]
    assert "Remediation: Validate and normalise uploaded filenames" in description
    assert "Commands:\ncurl -s -F" in description
    assert "Logs:\nuid=33(www-data)" in description

    summary = next(a for a in rce["Attribute"] if a["object_relation"] == "summary")
    tags = {tag["name"] for tag in summary["Tag"]}
    assert 'darkmoon:exploitation-status="exploited"' in tags
    assert 'darkmoon:severity="critical"' in tags
    assert 'misp-galaxy:mitre-attack-pattern="Exploit Public-Facing Application - T1190"' in tags

    assert _values(urls[0], "url") == ["https://app.example.test/upload"]
    reference = rce["ObjectReference"][0]
    assert reference["relationship_type"] == "affects"
    assert reference["referenced_uuid"] == urls[0]["uuid"]

    ssrf = vulnerabilities[2]
    assert _values(ssrf, "id") == []
    assert _values(ssrf, "cvss-string") == []
    assert _values(ssrf, "references") == []


def test_accepts_bare_list_of_findings():
    findings = json.loads(FIXTURE.read_text())["findings"]
    result = darkmoon_import.handler(_request(json.dumps(findings).encode()))
    assert len(_objects(result, "vulnerability")) == 3


def test_exclude_unconfirmed():
    result = darkmoon_import.handler(_request(FIXTURE.read_bytes(), include_unconfirmed=False))
    summaries = [_values(obj, "summary")[0] for obj in _objects(result, "vulnerability")]
    assert len(summaries) == 2
    assert "Server-side request forgery in URL preview feature" not in summaries


def test_rejects_other_json():
    gitleaks_like = json.dumps({"findings": [{"title": "x", "severity": "high"}]}).encode()
    assert "error" in darkmoon_import.handler(_request(gitleaks_like))
    assert "error" in darkmoon_import.handler(_request(b"{}"))
    assert "error" in darkmoon_import.handler(_request(b"not json"))


def test_introspection_and_version():
    assert darkmoon_import.introspection()["format"] == "misp_standard"
    assert darkmoon_import.version()["module-type"] == ["import"]
