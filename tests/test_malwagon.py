"""Tests for the Malwagon expansion modules.

Every HTTP call is mocked, so the suite needs no API key and no network. The
placeholder key below is deliberately not shaped like a real Malwagon token.
"""

import base64
import json
import pathlib
from unittest.mock import patch

import pytest

from misp_modules.modules.expansion import _malwagon_api, malwagon, malwagon_submit

API_KEY = "<your-api-key>"
UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# The zip fixture already in this directory: EICAR.com, encrypted with the
# password MISP uses for malware-sample attributes.
INFECTED_ZIP = pathlib.Path(__file__).resolve().parent.joinpath("infected.zip").read_bytes()
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-"

FINISHED_SCAN = {
    "scan_id": "scan-1",
    "status": "finished",
    "verdict": "malicious",
    "score": 92,
    "module": "file",
    "mime": "application/x-dosexec",
    "size": 4096,
    "tags": ["trojan", "loader"],
    "submitted_at": "2026-09-01T10:00:00Z",
    "finished_at": "2026-09-01T10:04:00Z",
}
RUNNING_SCAN = {"scan_id": "scan-1", "status": "running", "module": "file"}


class MockResponse:
    def __init__(self, payload=None, status_code=200, headers=None):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        if self.payload is None:
            raise ValueError("no json")
        return self.payload


class Recorder:
    """A requests.request replacement that records calls and replays answers."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        for fragment, answer in self.answers:
            if fragment in url:
                if callable(answer):
                    return answer(len([c for c in self.calls if fragment in c["url"]]))
                return answer
        return MockResponse({}, status_code=404)

    def urls(self):
        return [call["url"] for call in self.calls]


def lookup_query(value=SHA256, type_="sha256", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    return json.dumps(
        {
            "module": "malwagon",
            "attribute": attribute,
            "config": config if config is not None else {"apikey": API_KEY},
        }
    )


def submit_query(config=None, **request):
    payload = {"module": "malwagon_submit", "config": config if config is not None else {"apikey": API_KEY}}
    payload.update(request)
    return json.dumps(payload)


def objects_by_name(results):
    return {obj["name"]: obj for obj in results["results"]["Object"]}


def all_tags(results):
    tags = []
    for obj in results["results"]["Object"]:
        for attribute in obj["Attribute"]:
            tags.extend(tag["name"] for tag in attribute.get("Tag", []))
    return tags


class FakeClock:
    """A clock the polling loop can be driven against without real waiting."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def _fake_clock():
    """The submit module polls; nothing here should actually wait."""
    clock = FakeClock()
    with patch.object(malwagon_submit.time, "sleep", clock.sleep):
        with patch.object(malwagon_submit.time, "monotonic", clock.monotonic):
            yield clock


# --------------------------------------------------------------------------
# Lookup module
# --------------------------------------------------------------------------


def test_lookup_returns_file_and_sandbox_report_objects():
    recorder = Recorder([("/hashes/", MockResponse({"scans": {"items": [FINISHED_SCAN], "returned": 0, "total": 0, "truncated": False}}))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    objects = objects_by_name(results)
    assert set(objects) == {"file", "sandbox-report"}
    file_values = {a["object_relation"]: a["value"] for a in objects["file"]["Attribute"]}
    assert file_values["sha256"] == SHA256
    assert file_values["mimetype"] == "application/x-dosexec"
    assert file_values["size-in-bytes"] == 4096


def test_lookup_maps_the_verdict_onto_misp_taxonomies():
    """
    The point of the mapping is that a MISP filter on threat level sees the
    result. A raw vendor string in a text attribute would be invisible to it.
    """
    recorder = Recorder([("/hashes/", MockResponse([FINISHED_SCAN]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert 'misp:threat-level="high-risk"' in all_tags(results)
    assert 'ioc:artifact-state="malicious"' in all_tags(results)


def test_lookup_maps_a_clean_verdict_to_no_risk():
    clean = dict(FINISHED_SCAN, verdict="clean", score=0)
    recorder = Recorder([("/hashes/", MockResponse([clean]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert 'misp:threat-level="no-risk"' in all_tags(results)
    assert 'ioc:artifact-state="not-malicious"' in all_tags(results)


def test_remote_tags_are_reported_as_text_not_as_misp_tags():
    """
    A tag string chosen by the remote service must not become a MISP tag: that
    would let the service write into the instance's taxonomies.
    """
    hostile = dict(FINISHED_SCAN, tags=['tlp:red', 'ioc:artifact-state="not-malicious"'])
    recorder = Recorder([("/hashes/", MockResponse([hostile]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert "tlp:red" not in all_tags(results)
    report = objects_by_name(results)["sandbox-report"]
    assert any("tlp:red" in a["value"] for a in report["Attribute"] if a["object_relation"] == "results")


def test_lookup_accepts_a_composite_filename_sha256():
    recorder = Recorder([("/hashes/", MockResponse([FINISHED_SCAN]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query(f"sample.exe|{SHA256}", "filename|sha256"))

    assert SHA256 in recorder.urls()[0]
    assert "results" in results


def test_lookup_refuses_a_value_that_is_not_a_sha256():
    """The digest is interpolated into the request path, so it is validated first."""
    with patch.object(_malwagon_api.requests, "request", Recorder([])) as recorder:
        results = malwagon.handler(lookup_query("../scans/scan-1", "sha256"))

    assert "error" in results
    assert recorder.calls == []


def test_lookup_reports_an_unknown_digest_without_inventing_a_result():
    recorder = Recorder([("/hashes/", MockResponse(None, status_code=404))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert results == {"error": "Malwagon has no analysis for this digest."}


def test_lookup_requires_an_api_key():
    assert "error" in malwagon.handler(lookup_query(config={}))


def test_lookup_caps_the_number_of_reports():
    scans = [dict(FINISHED_SCAN, scan_id=f"scan-{i}") for i in range(20)]
    recorder = Recorder([("/hashes/", MockResponse({"scans": scans}))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query(config={"apikey": API_KEY, "max_results": 3}))

    reports = [o for o in results["results"]["Object"] if o["name"] == "sandbox-report"]
    assert len(reports) == 3


# --------------------------------------------------------------------------
# Transport hardening
# --------------------------------------------------------------------------


def test_the_api_key_travels_in_a_header_and_never_in_the_url():
    recorder = Recorder([("/hashes/", MockResponse([FINISHED_SCAN]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon.handler(lookup_query())

    call = recorder.calls[0]
    assert call["headers"]["Authorization"] == f"Bearer {API_KEY}"
    assert API_KEY not in call["url"]


def test_every_request_sets_a_timeout_and_refuses_redirects():
    """
    A redirect would re-send the bearer token to a host named by the response,
    and requests has no default timeout, so both are set explicitly.
    """
    recorder = Recorder([("/hashes/", MockResponse([FINISHED_SCAN]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon.handler(lookup_query())

    call = recorder.calls[0]
    assert call["allow_redirects"] is False
    assert call["timeout"] == _malwagon_api.DEFAULT_TIMEOUT


def test_a_redirect_is_reported_rather_than_followed():
    redirect = MockResponse(None, status_code=302, headers={"Location": "https://example.invalid/"})
    recorder = Recorder([("/hashes/", redirect)])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert "redirect" in results["error"]


def test_a_rate_limit_surfaces_retry_after_and_does_not_retry():
    throttled = MockResponse(None, status_code=429, headers={"Retry-After": "42"})
    recorder = Recorder([("/hashes/", throttled)])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert "42" in results["error"]
    assert len(recorder.calls) == 1


def test_a_missing_scope_is_distinguished_from_a_bad_key():
    recorder = Recorder([("/hashes/", MockResponse(None, status_code=403))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon.handler(lookup_query())

    assert "scope" in results["error"]


def test_a_non_http_api_url_is_rejected():
    results = malwagon.handler(lookup_query(config={"apikey": API_KEY, "api_url": "file:///etc/passwd"}))
    assert "error" in results


# --------------------------------------------------------------------------
# Submit module
# --------------------------------------------------------------------------


def test_a_malware_sample_is_unzipped_with_the_infected_password_before_submission():
    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": FINISHED_SCAN}, status_code=202)),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(
            submit_query(
                **{
                    "malware-sample": "EICAR.com|d41d8cd98f00b204e9800998ecf8427e",
                    "data": base64.b64encode(INFECTED_ZIP).decode(),
                }
            )
        )

    posted = [call for call in recorder.calls if call["method"] == "POST"][0]
    assert posted["files"]["file"][1] == EICAR
    assert "results" in results


def test_an_attachment_is_only_base64_decoded():
    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": FINISHED_SCAN}, status_code=202)),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon_submit.handler(
            submit_query(attachment="report.doc", data=base64.b64encode(b"plain bytes").decode())
        )

    posted = [call for call in recorder.calls if call["method"] == "POST"][0]
    assert posted["files"]["file"][1] == b"plain bytes"


def test_a_known_digest_is_answered_from_the_lookup_without_spending_submit_quota():
    """
    A lookup is free and instant where a detonation costs minutes and one of a
    small number of submits, so the module must not detonate what is already known.
    """
    recorder = Recorder([("/hashes/", MockResponse([FINISHED_SCAN]))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(
            submit_query(attachment="sample.bin", data=base64.b64encode(b"known").decode())
        )

    assert [call["method"] for call in recorder.calls] == ["GET"]
    assert "results" in results


def test_always_submit_forces_a_fresh_detonation():
    recorder = Recorder([("/scans/file", MockResponse({"scan": FINISHED_SCAN}, status_code=202))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon_submit.handler(
            submit_query(
                attachment="sample.bin",
                data=base64.b64encode(b"known").decode(),
                config={"apikey": API_KEY, "always_submit": "true"},
            )
        )

    assert [call["method"] for call in recorder.calls] == ["POST"]


def test_a_file_submission_is_private_by_default():
    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": FINISHED_SCAN}, status_code=202)),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon_submit.handler(submit_query(attachment="s.bin", data=base64.b64encode(b"x").decode()))

    posted = [call for call in recorder.calls if call["method"] == "POST"][0]
    assert posted["data"]["private"] == "true"
    # No sandbox image is named: the platform picks one from the sample.
    assert "os" not in posted["data"]


def test_a_url_is_submitted_as_a_url_module_scan():
    recorder = Recorder([("/scans", MockResponse({"scan": dict(FINISHED_SCAN, module="url")}, status_code=202))])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(submit_query(url="http://example.invalid/payload"))

    posted = recorder.calls[0]
    assert posted["json"] == {"module": "url", "target": "http://example.invalid/payload", "private": True}
    assert objects_by_name(results).keys() == {"sandbox-report"}


def test_the_scan_is_polled_until_it_finishes():
    def status(call_number):
        return MockResponse({"scan": RUNNING_SCAN if call_number < 3 else FINISHED_SCAN})

    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": RUNNING_SCAN}, status_code=202)),
            ("/scans/scan-1", status),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(submit_query(attachment="s.bin", data=base64.b64encode(b"x").decode()))

    assert len([c for c in recorder.calls if "/scans/scan-1" in c["url"]]) == 3
    assert 'misp:threat-level="high-risk"' in all_tags(results)


def test_a_scan_still_running_at_the_deadline_returns_the_permalink_instead_of_an_error():
    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": RUNNING_SCAN}, status_code=202)),
            ("/scans/scan-1", MockResponse({"scan": RUNNING_SCAN})),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(
            submit_query(
                attachment="s.bin",
                data=base64.b64encode(b"x").decode(),
                config={"apikey": API_KEY, "poll_timeout": 1},
            )
        )

    report = objects_by_name(results)["sandbox-report"]
    permalinks = [a["value"] for a in report["Attribute"] if a["object_relation"] == "permalink"]
    assert permalinks == ["https://malwagon.com/s/scan-1"]
    assert all_tags(results) == []


def test_a_restrictive_tlp_tag_blocks_the_submission():
    recorder = Recorder([])
    query = json.dumps(
        {
            "module": "malwagon_submit",
            "config": {"apikey": API_KEY},
            "attribute": {"type": "url", "value": "http://example.invalid/", "uuid": UUID, "Tag": [{"name": "tlp:red"}]},
            "url": "http://example.invalid/",
        }
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(query)

    assert "tlp:red" in results["error"]
    assert recorder.calls == []


def test_a_tlp_tag_within_the_ceiling_is_allowed():
    recorder = Recorder([("/scans", MockResponse({"scan": FINISHED_SCAN}, status_code=202))])
    query = json.dumps(
        {
            "module": "malwagon_submit",
            "config": {"apikey": API_KEY},
            "attribute": {
                "type": "url",
                "value": "http://example.invalid/",
                "uuid": UUID,
                "Tag": [{"name": "tlp:green"}],
            },
            "url": "http://example.invalid/",
        }
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(query)

    assert "results" in results


def test_an_undecodable_sample_never_echoes_sample_bytes():
    """
    The error goes into the MISP interface and the module log, so it must be a
    fixed string and not anything derived from the sample.
    """
    payload = base64.b64encode(b"not a zip, but recognisable content").decode()
    recorder = Recorder([])
    with patch.object(_malwagon_api.requests, "request", recorder):
        results = malwagon_submit.handler(
            submit_query(**{"malware-sample": "x.zip|deadbeef", "data": payload})
        )

    assert results == {"error": "The malware-sample attribute could not be unpacked."}
    assert recorder.calls == []


def test_a_filename_cannot_carry_a_path_or_a_separator_into_the_multipart_body():
    recorder = Recorder(
        [
            ("/hashes/", MockResponse(None, status_code=404)),
            ("/scans/file", MockResponse({"scan": FINISHED_SCAN}, status_code=202)),
        ]
    )
    with patch.object(_malwagon_api.requests, "request", recorder):
        malwagon_submit.handler(
            submit_query(attachment='../../etc/pa"sswd\r\nX: y', data=base64.b64encode(b"x").decode())
        )

    posted = [call for call in recorder.calls if call["method"] == "POST"][0]
    name = posted["files"]["file"][0]
    assert not set(name) & set('/\\"\r\n')


def test_submit_rejects_an_unsupported_request():
    assert "error" in malwagon_submit.handler(submit_query(domain="example.invalid"))


def test_submit_requires_an_api_key():
    assert "error" in malwagon_submit.handler(submit_query(url="http://example.invalid/", config={}))


# --------------------------------------------------------------------------
# Module contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize("module", (malwagon, malwagon_submit))
def test_the_module_contract_is_complete(module):
    """generate.py exits if any of these is missing, which breaks the docs build."""
    info = module.version()
    for field in ("name", "description", "module-type", "author", "version", "logo"):
        assert field in info
    assert info["config"] == module.moduleconfig
    assert module.introspection() == module.mispattributes
    assert module.handler(False) is False


def test_hover_is_only_offered_by_the_free_lookup():
    """Hover fires on viewing an attribute; a detonation must never be triggered that way."""
    assert "hover" in malwagon.moduleinfo["module-type"]
    assert "hover" not in malwagon_submit.moduleinfo["module-type"]
