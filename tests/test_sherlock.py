import csv
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from misp_modules.modules.expansion import sherlock

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
HEADER = ["username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"]


def _query(value="alice", attribute_type="target-user", config=None):
    return json.dumps({"attribute": {"type": attribute_type, "value": value, "uuid": UUID}, "config": config or {}})


def _row(site="GitHub", status="Claimed", username="alice", url="https://github.com/alice"):
    return [username, site, "https://example.org", url, status, "200", "0.1"]


def _run(query=None, rows=None):
    directories = []

    def execute(command, **kwargs):
        directory = Path(command[command.index("--folderoutput") + 1])
        directories.append(directory)
        assert Path(kwargs["cwd"]) == directory
        assert command[-2] == "--"
        assert "--print-all" in command
        assert kwargs["check"] is True
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert not kwargs.get("shell", False)
        with (directory / f"{command[-1]}.csv").open("w", newline="") as report:
            writer = csv.writer(report)
            writer.writerow(HEADER)
            writer.writerows(rows if rows is not None else [_row(username=command[-1])])

    with (
        patch.object(sherlock.shutil, "which", return_value="/usr/bin/sherlock"),
        patch.object(sherlock.subprocess, "run", side_effect=execute) as run,
    ):
        result = sherlock.handler(query or _query())
    assert all(not directory.exists() for directory in directories)
    return result, run


def _values(obj):
    return {attribute["object_relation"]: attribute["value"] for attribute in obj["Attribute"]}


def test_only_claimed_accounts_become_referenced_misp_objects():
    rows = [
        _row(),
        _row(),  # Duplicate rows do not duplicate accounts.
        _row("Reddit", url="https://reddit.com/user/alice"),
        _row("Absent", "Available"),
        _row("Failed", "Unknown"),
        _row("Blocked", "WAF"),
        _row("Invalid", "Illegal"),
    ]
    result, _ = _run(rows=rows)
    assert result["results"]["Attribute"][0]["uuid"] == UUID
    objects = result["results"]["Object"]
    assert len(objects) == 2
    assert _values(objects[0]) == {
        "username": "alice",
        "account-type": "GitHub",
        "link": "https://github.com/alice",
    }
    for obj in objects:
        assert obj["name"] == "user-account"
        assert "2 site lookups failed" in obj["comment"]
        assert "does not verify identity or email ownership" in obj["comment"]
        assert all(attribute["to_ids"] is False for attribute in obj["Attribute"])
        assert [(ref["referenced_uuid"], ref["relationship_type"]) for ref in obj["ObjectReference"]] == [
            (UUID, "related-to")
        ]


@pytest.mark.parametrize("attribute_type", sherlock.mispattributes["input"])
def test_supported_attribute_types(attribute_type):
    value = "alice+tag@example.org" if attribute_type in sherlock._EMAIL_TYPES else "alice"
    candidate = value.split("@")[0]
    result, run = _run(_query(value, attribute_type))
    assert run.call_args.args[0][-1] == candidate
    values = _values(result["results"]["Object"][0])
    assert values["username"] == candidate
    assert "email" not in values  # No claimed email-to-account attribution.
    if attribute_type == "github-username":
        command = run.call_args.args[0]
        assert command[command.index("--site") + 1] == "GitHub"


@pytest.mark.parametrize(
    "value, candidate",
    [
        (" @alice ", "alice"),
        ("alice@example.org", "alice@example.org"),
        ("@alice@example.org", "alice@example.org"),
        ("Alice Smith", "Alice Smith"),
        ("élise", "élise"),
    ],
)
def test_text_is_a_literal_username(value, candidate):
    result, run = _run(_query(value, "text"))
    assert run.call_args.args[0][-1] == candidate
    assert _values(result["results"]["Object"][0])["username"] == candidate


def test_configuration_and_leading_dash_are_passed_as_separate_arguments():
    query = _query("--version", config={"sites": "GitHub, Reddit ", "timeout": "2.5", "scan_timeout": "42"})
    result, run = _run(query)
    assert "results" in result
    command = run.call_args.args[0]
    assert command[-2:] == ["--", "--version"]
    assert command[command.index("--timeout") + 1] == "2.5"
    assert [command[i + 1] for i, value in enumerate(command) if value == "--site"] == ["GitHub", "Reddit"]
    assert run.call_args.kwargs["timeout"] == 42


@pytest.mark.parametrize("value", ["", " ", None, 42, "../alice", "a/b", "a\\b", "a\x00b", "a\nb", "a{?}b", "é" * 121])
def test_invalid_candidates_do_not_execute_sherlock(value):
    result, run = _run(_query(value))
    assert "error" in result
    run.assert_not_called()


@pytest.mark.parametrize("value", ["alice", "@example.org", "alice@", "alice@@example.org", "alice smith@example.org"])
def test_invalid_email_does_not_execute_sherlock(value):
    result, run = _run(_query(value, "email"))
    assert "error" in result
    run.assert_not_called()


@pytest.mark.parametrize("name", ["timeout", "scan_timeout"])
@pytest.mark.parametrize("value", ["bad", 0, -1, "nan", "inf", True, [], {}])
def test_invalid_timeouts_do_not_execute_sherlock(name, value):
    result, run = _run(_query(config={name: value}))
    assert name in result["error"]
    run.assert_not_called()


@pytest.mark.parametrize("payload", ["not-json", "[]", "null", "{}", '{"attribute": []}'])
def test_malformed_request(payload):
    result, run = _run(payload)
    assert "error" in result
    run.assert_not_called()


def test_unsupported_type_and_invalid_config():
    result, run = _run(_query(attribute_type="domain"))
    assert "Unsupported" in result["error"]
    run.assert_not_called()
    request = json.loads(_query())
    request["config"] = ["invalid"]
    result, run = _run(json.dumps(request))
    assert "config" in result["error"]
    run.assert_not_called()


def test_no_matches_are_distinguished_from_failed_lookups():
    result, _ = _run(rows=[_row(status="Available")])
    assert "no matching accounts" in result["error"]
    result, _ = _run(rows=[_row(status="Unknown"), _row("Blocked", "WAF")])
    assert "2 site lookups failed" in result["error"]
    assert "incomplete" in result["error"]


@pytest.mark.parametrize(
    "row", [_row(username="someone-else"), _row(status="unexpected"), _row(url="javascript:alert(1)"), _row(url="")]
)
def test_invalid_csv_rows_are_errors(row):
    result, _ = _run(rows=[row])
    assert "invalid" in result["error"]


def test_invalid_csv_header(tmp_path):
    path = tmp_path / "alice.csv"
    path.write_text("unexpected,columns\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid CSV report"):
        sherlock._read_report(path, "alice")


def test_missing_installation_has_actionable_error():
    with patch.object(sherlock.shutil, "which", return_value=None):
        result = sherlock.handler(_query())
    assert "Install sherlock-project" in result["error"]


@pytest.mark.parametrize(
    "exception, message",
    [
        (subprocess.TimeoutExpired("sherlock", 120), "exceeded scan_timeout"),
        (subprocess.CalledProcessError(1, "sherlock"), "exited with status 1"),
        (OSError("unavailable"), "Unable to execute Sherlock"),
    ],
)
def test_execution_errors_and_temporary_directory_cleanup(exception, message):
    directories = []

    def fail(command, **kwargs):
        directories.append(Path(kwargs["cwd"]))
        raise exception

    with (
        patch.object(sherlock.shutil, "which", return_value="/usr/bin/sherlock"),
        patch.object(sherlock.subprocess, "run", side_effect=fail),
    ):
        result = sherlock.handler(_query())
    assert message in result["error"]
    assert all(not directory.exists() for directory in directories)


@pytest.mark.skipif(sys.platform == "win32", reason="Fixture executable uses a POSIX shebang")
def test_real_subprocess_with_a_local_cli_fixture(tmp_path):
    executable = tmp_path / "fixture-sherlock"
    executable.write_text(
        f"#!{sys.executable}\nimport argparse, csv, pathlib\nparser = argparse.ArgumentParser()\nfor flag in ('--csv',"
        " '--print-all', '--no-color'):\n    parser.add_argument(flag, action='store_true',"
        " required=True)\nparser.add_argument('--timeout', type=float,"
        " required=True)\nparser.add_argument('--folderoutput', required=True)\nparser.add_argument('username')\nargs"
        " = parser.parse_args()\ndirectory = pathlib.Path(args.folderoutput)\nassert pathlib.Path.cwd() =="
        " directory\nwith (directory / (args.username + '.csv')).open('w', newline='') as f:\n    writer ="
        f" csv.writer(f)\n    writer.writerow({HEADER!r})\n    writer.writerow([args.username, 'GitHub',"
        " 'https://github.com', 'https://github.com/alice', 'Claimed', 200, .1])\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    result = sherlock.handler(_query("--version", config={"sherlock_path": str(executable)}))
    assert _values(result["results"]["Object"][0])["username"] == "--version"


def test_metadata_and_empty_call():
    assert sherlock.handler() is False
    assert sherlock.introspection()["format"] == "misp_standard"
    assert sherlock.version()["config"] == sherlock.moduleconfig
    assert "expansion" in sherlock.version()["module-type"]
