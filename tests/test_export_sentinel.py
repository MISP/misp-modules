import json
import subprocess
from unittest.mock import Mock

import pytest

from misp_modules.modules.action_mod import export_sentinel as export

EVENT_UUID = "d7f4a832-5f8d-4c4b-a7ab-7b33c4b1a129"


def request(event_uuid=EVENT_UUID, **fields):
    return json.dumps({"data": {"Event": {"uuid": event_uuid}}, **fields})


@pytest.fixture
def installation(tmp_path, monkeypatch):
    # A symlink is deliberate: resolving it would lose the virtual environment.
    venv = tmp_path / "virtual environment"
    (venv / "bin").mkdir(parents=True)
    interpreter = tmp_path / "python"
    interpreter.touch(mode=0o755)
    python = venv / "bin" / "python"
    python.symlink_to(interpreter)
    script = tmp_path / "exporter" / "script.py"
    script.parent.mkdir()
    script.touch()
    monkeypatch.setenv("EXPORT_SENTINEL_VENV", str(venv))
    monkeypatch.setenv("EXPORT_SENTINEL_SCRIPT", str(script))
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(export.subprocess, "run", run)
    return venv, python, script, run


def test_export_uses_server_paths_and_normalized_uuid(installation):
    _, python, script, run = installation
    assert export.handler(request(EVENT_UUID.upper())) == {"data": True}
    run.assert_called_once_with(
        [str(python), str(script), EVENT_UUID],
        cwd=str(script.parent),
        capture_output=True,
        text=True,
        timeout=300,
        shell=False,
    )


@pytest.mark.parametrize("container", ["params", "config"])
@pytest.mark.parametrize("key", ["misp2_venv", "misp2_script"])
def test_request_cannot_choose_executable_paths(installation, container, key):
    *_, run = installation
    assert export.handler(request(**{container: {key: "/attacker/controlled"}})) == {"data": False}
    run.assert_not_called()


@pytest.mark.parametrize("setting", ["EXPORT_SENTINEL_VENV", "EXPORT_SENTINEL_SCRIPT"])
@pytest.mark.parametrize("value", [None, "", "relative/path"])
def test_missing_or_relative_server_settings_fail_closed(installation, monkeypatch, setting, value):
    *_, run = installation
    if value is None:
        monkeypatch.delenv(setting)
    else:
        monkeypatch.setenv(setting, value)
    assert export.handler(request()) == {"data": False}
    run.assert_not_called()


@pytest.mark.parametrize("target", ["python", "script"])
def test_missing_files_fail_without_running(installation, target):
    _, python, script, run = installation
    (python if target == "python" else script).unlink()
    assert export.handler(request()) == {"data": False}
    run.assert_not_called()


def test_interpreter_must_be_executable(installation):
    _, python, _, run = installation
    python.chmod(0o644)
    assert export.handler(request()) == {"data": False}
    run.assert_not_called()


@pytest.mark.parametrize("event_uuid", [None, "", "not-a-uuid", "--help", "$(id)", [EVENT_UUID], 42])
def test_invalid_event_uuid_never_runs_exporter(installation, event_uuid):
    *_, run = installation
    assert export.handler(request(event_uuid)) == {"data": False}
    run.assert_not_called()


@pytest.mark.parametrize("payload", ["{", "null", "[]", '{"data": null}', '{"data": {"Event": []}}', '{"params": []}'])
def test_malformed_requests_fail_without_running(installation, payload):
    *_, run = installation
    assert export.handler(payload) == {"data": False}
    run.assert_not_called()


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("exporter", 300), OSError("cannot execute")])
def test_execution_errors_preserve_failure_result(installation, failure):
    *_, run = installation
    run.side_effect = failure
    assert export.handler(request()) == {"data": False}


def test_exporter_nonzero_status_preserves_failure_result(installation):
    *_, run = installation
    run.return_value = subprocess.CompletedProcess([], 1, "", "export failed")
    assert export.handler(request()) == {"data": False}


def test_executable_paths_are_not_advertised_as_workflow_settings():
    assert export.introspection()["config"]["params"] == {}
    assert export.version()["config"]["params"] == {}
