import base64
import json
from unittest.mock import Mock, patch

import pytest

from misp_modules.modules.expansion import assemblyline_submit as module

API_URL = "https://assemblyline.example"
SID = "test-submission-id"


def response(payload, status=200):
    result = Mock(ok=status < 400, status_code=status)
    result.json.return_value = {"api_response": payload}
    return result


def query(kind="url"):
    request = {
        "config": {"apiurl": API_URL, "user_id": "test-user", "apikey": "test-key"},
        kind: "https://example.com/sample",
    }
    if kind != "url":
        request[kind] = "sample.bin" if kind == "attachment" else "sample.bin|0123456789abcdef0123456789abcdef"
        request["data"] = base64.b64encode(b"sample bytes").decode()
    return json.dumps(request)


@pytest.mark.parametrize("payload", [{"sid": SID}, {"submission": {"sid": SID}}], ids=["flat", "nested"])
@pytest.mark.parametrize("kind", ["url", "attachment", "malware-sample"])
def test_submission_returns_report_link(payload, kind):
    # Exercise response unwrapping and the handler together without contacting AssemblyLine.
    with patch(
        "misp_modules.modules.expansion._assemblyline_api.requests.Session.post",
        side_effect=[response({}), response(payload)],
    ) as post:
        result = module.handler(query(kind))

    assert result == {
        "results": [
            {
                "types": "link",
                "categories": "External analysis",
                "values": f"{API_URL}/submission/detail/{SID}",
            }
        ]
    }
    assert post.call_count == 2
    submission_call = post.call_args
    assert submission_call.args[0] == f"{API_URL}/api/v4/submit/"
    if kind == "url":
        assert submission_call.kwargs["json"]["url"] == "https://example.com/sample"
    else:
        filename, file_handle = submission_call.kwargs["files"]["bin"]
        assert filename == "sample.bin"
        assert file_handle.getvalue() == b"sample bytes"


@pytest.mark.parametrize(
    "payload", [{}, {"submission": {}}, {"submission": None}, {"sid": ""}, [], ["error"], True, 42, "error"]
)
def test_unexpected_submission_response_returns_error(payload):
    with patch(
        "misp_modules.modules.expansion._assemblyline_api.requests.Session.post",
        side_effect=[response({}), response(payload)],
    ):
        result = module.handler(query())

    assert result == {"error": "Unexpected response received from AssemblyLine.", "response": payload}


def test_submission_error_is_preserved():
    with patch(
        "misp_modules.modules.expansion._assemblyline_api.requests.Session.post",
        side_effect=[response({}), response({"error": "Submission rejected"})],
    ):
        result = module.handler(query())

    assert result == {"error": "Submission rejected"}
