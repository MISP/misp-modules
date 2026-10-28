import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from misp_modules.modules.expansion import cccs_yara

VALID_RULE = """rule example {
    meta:
        id = "6O9mUMvPhziJ72IXHf6muZ"
        fingerprint = "4aa0a23f28698898404d700cb363ddf06dd275f5798815e797113656a2a40ae8"
        version = "1.0"
        modified = "2026-10-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MISP"
        author = "analyst@MISP"
        description = "Example rule"
        category = "TECHNIQUE"
        technique = "TEST"
        reference = "https://example.org/report"
    condition:
        true
}
"""


@pytest.fixture(scope="module", autouse=True)
def local_attack_data(tmp_path_factory):
    # A small STIX store exercises actual upstream ATT&CK lookups offline.
    data_path = tmp_path_factory.mktemp("attack-data")
    technique_path = data_path / "enterprise-attack" / "attack-pattern"
    technique_path.mkdir(parents=True)
    technique_id = "attack-pattern--d4f0a3f9-f1e2-4c48-9df5-5c9e108f4f68"
    (technique_path / f"{technique_id}.json").write_text(
        json.dumps(
            {
                "type": "attack-pattern",
                "id": technique_id,
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            }
        ),
        encoding="utf-8",
    )
    with (
        patch.object(cccs_yara, "MITRE_STIX_DATA_PATH", data_path),
        patch("yara_validator.constants.MITRE_STIX_DATA_PATH", data_path),
        patch("git.Repo.clone_from", side_effect=AssertionError("Validation must not download ATT&CK data")),
    ):
        yield data_path


def validate(rule):
    response = cccs_yara.handler(json.dumps({"yara": rule}))
    assert "error" not in response, response
    assert response["results"][0]["types"] == ["text"]
    return response["results"][0]["values"]


def test_valid_metadata_and_standard_attribute_input():
    summary = validate(VALID_RULE)
    assert summary == "Rule example: CCCS YARA metadata valid."
    request = {"attribute": {"type": "yara", "value": VALID_RULE}}
    response = cccs_yara.handler(json.dumps(request))
    assert response["results"][0]["values"] == summary
    assert request["attribute"]["value"] == VALID_RULE


def test_missing_metadata_is_reported_without_generating_it():
    assert "metadata: No Metadata Present" in validate("rule missing { condition: true }")
    summary = validate(VALID_RULE.replace('        id = "6O9mUMvPhziJ72IXHf6muZ"\n', ""))
    assert "metadata invalid" in summary
    assert "id:" in summary and "Missing metadata" in summary


def test_invalid_and_duplicate_metadata():
    summary = validate(VALID_RULE.replace('status = "RELEASED"', 'status = "INVALID"'))
    assert "metadata invalid" in summary
    assert "status: Field has Invalid Value" in summary
    summary = validate(VALID_RULE.replace('status = "RELEASED"', 'status = "RELEASED"\nstatus = "TESTING"'))
    assert "status: Too many instances" in summary


def test_warnings_preserve_validity():
    summary = validate(VALID_RULE.replace('        reference = "https://example.org/report"\n', ""))
    assert "metadata valid" in summary
    assert "Warnings:\nreference: Source was given without a reference." in summary


def test_multiple_rules_report_each_name_and_state():
    summary = validate(VALID_RULE + "\nrule missing { condition: true }\n")
    assert "Rule example: CCCS YARA metadata valid." in summary
    assert "Rule missing: CCCS YARA metadata invalid." in summary
    # Reversing the rules also checks upstream state is reset between rules.
    summary = validate("rule missing { condition: true }\n" + VALID_RULE)
    assert "Rule example: CCCS YARA metadata valid." in summary


def test_attack_metadata_uses_local_stix_store():
    rule = VALID_RULE.replace("    condition:", '        mitre_att = "T1059"\n    condition:')
    assert "metadata valid" in validate(rule)
    summary = validate(rule.replace("T1059", "T9999"))
    assert "metadata invalid" in summary
    assert "mitre_att: Field has Invalid Value" in summary


def test_invalid_syntax_and_no_rules():
    assert "YARA syntax error" in validate("rule broken { condition: }")
    assert validate("// no rules here") == "No YARA rules found."


def test_includes_are_rejected_before_upstream_processing(tmp_path):
    included = tmp_path / "local.yara"
    included.write_text(VALID_RULE, encoding="utf-8")
    with patch("yara_validator.validator.run_yara_validator") as validator:
        summary = validate(f'include "{included}"\nrule outer {{ condition: true }}')
    assert "includes are disabled" in summary
    validator.assert_not_called()


def test_missing_data_fails_before_importing_validator(tmp_path):
    # A fresh interpreter verifies missing data never triggers upstream's
    # import-time clone, even when no other test has imported the validator yet.
    script = """
import json
import sys
from unittest.mock import patch
with patch("git.Repo.clone_from", side_effect=AssertionError("Unexpected clone")):
    from misp_modules.modules.expansion import cccs_yara
    assert "yara_validator.validator" not in sys.modules
    assert cccs_yara.version()["name"] == "CCCS YARA Metadata Validator"
    cccs_yara.MITRE_STIX_DATA_PATH = sys.argv[1]
    response = cccs_yara.handler(json.dumps({"yara": "rule test { condition: true }"}))
    assert "MITRE_STIX_DATA_PATH" in response["error"], response
    assert "yara_validator.validator" not in sys.modules
"""
    for path in (tmp_path, tmp_path / "missing"):
        subprocess.run([sys.executable, "-c", script, str(path)], check=True, capture_output=True, text=True)


def test_temporary_input_is_removed_on_success_and_failure():
    from yara_validator.validator import run_yara_validator

    paths = []

    def validator(path, **kwargs):
        paths.append(path)
        assert Path(path).read_text(encoding="utf-8") == VALID_RULE
        assert kwargs["generate_values"] is False
        return run_yara_validator(path, **kwargs)

    with patch("yara_validator.validator.run_yara_validator", side_effect=validator):
        validate(VALID_RULE)
    assert not paths[0].parent.exists()

    def failure(path, **kwargs):
        paths.append(path)
        raise RuntimeError("Validation failure")

    with patch("yara_validator.validator.run_yara_validator", side_effect=failure):
        assert "error" in cccs_yara.handler(json.dumps({"yara": VALID_RULE}))
    assert not paths[-1].parent.exists()


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"yara": ""},
        {"yara": "   "},
        {"yara": 123},
        {"attribute": None},
        {"attribute": {"type": "text", "value": VALID_RULE}},
        {"attribute": {"type": "yara"}},
    ],
)
def test_invalid_requests(payload):
    assert "error" in cccs_yara.handler(json.dumps(payload))


def test_module_interface():
    assert cccs_yara.handler() is False
    assert "error" in cccs_yara.handler("{")
    assert cccs_yara.introspection() == {"input": ["yara"], "output": ["text"]}
    info = cccs_yara.version()
    assert info["module-type"] == ["expansion", "hover"]
    assert info["config"] == []


def test_yara_and_pandoc_parsers_can_coexist():
    # plyara 2.2.7+ ships a top-level ply package that overwrites Pandoc's
    # dependency and crashes both server startup and documentation discovery.
    # Use a fresh interpreter so already imported modules cannot mask this.
    script = """
import plyara
from misp_modules.modules.expansion import cccs_yara, convert_markdown_to_pdf
rules = plyara.Plyara().parse_string("rule example { condition: true }")
assert rules[0]["rule_name"] == "example"
assert cccs_yara.introspection()["input"] == ["yara"]
assert convert_markdown_to_pdf.version()["name"] == "Markdown to PDF converter"
"""
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
