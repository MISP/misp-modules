"""Shared client and MISP result builder for the Malwagon expansion modules.

The leading underscore keeps this file out of module discovery: misp_modules
only imports files that do not start with "_", so this is a library, not a
module. Same arrangement as _assemblyline_api.py.

Two modules use it: malwagon (free, instant hash lookup) and malwagon_submit
(detonation, which costs a submit quota). Both end up holding the same scan
summary, so the parsing and the MISP object building live here once.
"""

import re
from urllib.parse import quote, urlparse

import requests
from pymisp import MISPEvent, MISPObject

DEFAULT_API_URL = "https://malwagon.com/api/v1"

# Every request carries an explicit timeout. requests has no default one, so a
# hung endpoint would otherwise hold a MISP enrichment worker open forever.
DEFAULT_TIMEOUT = 30

USER_AGENT = "malwagon-misp/1.0 (+https://github.com/MISP/misp-modules)"

# The scan summary is an allowlist on the server side. Mirroring it here means a
# field added later cannot silently become an attribute nobody reviewed.
SCAN_SUMMARY_KEYS = (
    "scan_id",
    "status",
    "verdict",
    "score",
    "module",
    "mime",
    "size",
    "tags",
    "submitted_at",
    "finished_at",
)

# Map the vendor verdict onto MISP's own vocabulary rather than passing the
# string through raw: misp:threat-level is the platform's severity scale and
# ioc:artifact-state is what the correlation and filtering side reads.
VERDICT_TAGS = {
    "clean": ('misp:threat-level="no-risk"', 'ioc:artifact-state="not-malicious"'),
    "suspicious": ('misp:threat-level="medium-risk"',),
    "malicious": ('misp:threat-level="high-risk"', 'ioc:artifact-state="malicious"'),
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

# Remote strings become MISP attribute values. Cap them so a hostile or merely
# broken response cannot push an unbounded blob into an event.
MAX_VALUE_LENGTH = 512
MAX_TAGS = 32


class MalwagonError(Exception):
    """An error worth showing to the analyst in the MISP interface.

    Every message raised here is written by this file. Nothing derived from the
    submitted sample, and nothing derived from the API key, is ever put in one.
    """


def is_sha256(value):
    return bool(SHA256_RE.match(str(value or "").strip()))


def clean_text(value):
    """Flatten one remote value into something safe to put in an attribute."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) > MAX_VALUE_LENGTH:
        text = f"{text[:MAX_VALUE_LENGTH]}..."
    return text


def scan_summary(payload):
    """Keep only the documented summary keys, whatever wrapper they arrived in."""
    if not isinstance(payload, dict):
        return {}
    if isinstance(payload.get("scan"), dict):
        payload = payload["scan"]
    return {key: payload[key] for key in SCAN_SUMMARY_KEYS if payload.get(key) is not None}


def scan_summaries(payload):
    """Pull the list of scan summaries out of a hash-lookup response.

    The lookup answers with scans of one digest. Accepting either a bare list or
    a list under a container key means a wrapper change does not turn a real
    answer into "not found", which is the failure mode that misleads an analyst.
    """
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        candidates = None
        for key in ("scans", "results", "data"):
            value = payload.get(key)
            # Every list on this API arrives wrapped with its own accounting,
            # `{"items": [...], "returned": n, "total": n, "truncated": bool}`,
            # so that a truncated answer can never be mistaken for a complete
            # one. Unwrap that before looking for a bare list: reading only the
            # bare form turned a real answer into "not found", which is exactly
            # the failure mode this function exists to avoid.
            if isinstance(value, dict) and isinstance(value.get("items"), list):
                candidates = value["items"]
                break
            if isinstance(value, list):
                candidates = value
                break
        if candidates is None:
            single = scan_summary(payload)
            candidates = [single] if single else []
    else:
        candidates = []
    return [summary for summary in (scan_summary(item) for item in candidates) if summary]


def is_finished(summary):
    """Whether a scan has reached a terminal state.

    Keyed off the two documented facts - a verdict is absent while a scan is
    unfinished, and finished_at is set when it is done - rather than off a list
    of status strings, which is not part of the published contract.
    """
    return bool(summary.get("verdict") or summary.get("finished_at"))


class MalwagonClient:
    """Minimal Malwagon REST client built on requests."""

    def __init__(self, api_key, api_url=None, timeout=DEFAULT_TIMEOUT):
        if not api_key:
            raise MalwagonError("A Malwagon API key is required.")
        self.api_key = api_key
        self.api_url = self._validate_url(api_url or DEFAULT_API_URL)
        self.timeout = timeout

    @staticmethod
    def _validate_url(api_url):
        url = str(api_url).strip().rstrip("/")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise MalwagonError("The configured Malwagon API URL is not a valid http(s) URL.")
        return url

    def _headers(self):
        # Header only. The key never goes in a URL, a query string or a log line.
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

    def _request(self, method, path, **kwargs):
        try:
            response = requests.request(
                method,
                f"{self.api_url}{path}",
                headers=self._headers(),
                timeout=self.timeout,
                # A redirect would re-send the Authorization header to whatever
                # host the response names. Refuse instead of following.
                allow_redirects=False,
                **kwargs,
            )
        except requests.exceptions.RequestException:
            # The exception text can contain the full request URL; the message
            # here is written by us so nothing from the request can leak.
            raise MalwagonError("Could not reach the Malwagon API.")
        return self._handle(response)

    @staticmethod
    def _handle(response):
        status = response.status_code
        if status in (301, 302, 303, 307, 308):
            raise MalwagonError("The Malwagon API answered with a redirect, which is not followed.")
        if status == 401:
            raise MalwagonError("Malwagon rejected the API key.")
        if status == 403:
            raise MalwagonError("The Malwagon API key does not carry the scope this request needs.")
        if status == 404:
            return None
        if status == 429:
            retry_after = response.headers.get("Retry-After")
            # Report and stop. Retrying in a loop is what turns one throttled
            # user into a throttled tenant.
            if retry_after:
                raise MalwagonError(f"Malwagon rate limit reached, retry after {clean_text(retry_after)} seconds.")
            raise MalwagonError("Malwagon rate limit reached.")
        if status >= 400:
            raise MalwagonError(f"The Malwagon API answered with HTTP {status}.")
        try:
            return response.json()
        except ValueError:
            raise MalwagonError("The Malwagon API answered with a body that is not JSON.")

    def lookup_hash(self, sha256):
        if not is_sha256(sha256):
            raise MalwagonError("A Malwagon hash lookup needs a SHA256 digest.")
        # Validated against the regex above, so it cannot walk out of the path.
        return scan_summaries(self._request("GET", f"/hashes/{sha256.lower()}"))

    def scan_status(self, scan_id):
        return scan_summary(self._request("GET", f"/scans/{quote(str(scan_id), safe='')}"))

    def submit_file(self, filename, content, options=None):
        data = {key: value for key, value in (options or {}).items() if value is not None}
        payload = self._request(
            "POST",
            "/scans/file",
            files={"file": (filename or "sample", content)},
            data=data,
        )
        return scan_summary(payload)

    def submit_target(self, module, target, options=None):
        body = {"module": module, "target": target}
        body.update({key: value for key, value in (options or {}).items() if value is not None})
        return scan_summary(self._request("POST", "/scans", json=body))

    def report_url(self, scan_id):
        """Where a human reads the report for this scan.

        The API endpoint answers 401 without a bearer token, so pointing an
        analyst at it hands them a login wall instead of a report. The public
        permalink resolves anonymously for a scan that was left public, which
        is what a permalink in a MISP object is for. It is only ever attached
        to a scan we know is public; a private one has no page to link to.
        """
        base = self.api_url.split("/api/", 1)[0]
        return f"{base}/s/{quote(str(scan_id), safe='')}"


class MalwagonResults:
    """Builds the misp_standard result payload out of scan summaries."""

    def __init__(self, client, sha256=None, attribute_uuid=None):
        self.client = client
        self.sha256 = sha256.lower() if sha256 and is_sha256(sha256) else None
        self.attribute_uuid = attribute_uuid
        self.misp_event = MISPEvent()
        self.tagged = False

    def add_scan(self, summary):
        if not summary:
            return
        file_object, anchor = self._add_file_object(summary)
        report = self._add_report_object(summary)
        if report is None:
            return
        # One verdict tag per enrichment, on the indicator when there is one and
        # on the verdict line otherwise, so the tag is never orphaned.
        if not self.tagged:
            target = anchor if anchor is not None else self._verdict_attribute(report)
            if target is not None and self._tag(target, summary.get("verdict")):
                self.tagged = True
        if file_object is not None:
            report.add_reference(file_object.uuid, "analysed-with")

    def _add_file_object(self, summary):
        """A file object for the sample, when the scan describes one."""
        if not self.sha256:
            return None, None
        misp_object = MISPObject("file")
        anchor = misp_object.add_attribute("sha256", type="sha256", value=self.sha256)
        if summary.get("mime"):
            misp_object.add_attribute("mimetype", type="mime-type", value=clean_text(summary["mime"]))
        size = summary.get("size")
        if isinstance(size, int) and size >= 0:
            misp_object.add_attribute("size-in-bytes", type="size-in-bytes", value=size)
        if self.attribute_uuid:
            misp_object.add_reference(self.attribute_uuid, "related-to")
        self.misp_event.add_object(misp_object)
        return misp_object, anchor

    def _add_report_object(self, summary):
        scan_id = summary.get("scan_id")
        if not scan_id:
            return None
        misp_object = MISPObject("sandbox-report")
        # The report is only retrievable with a key, so this is a saas sandbox
        # in the object template's vocabulary, not a web one.
        misp_object.add_attribute("sandbox-type", type="text", value="saas")
        misp_object.add_attribute("saas-sandbox", type="text", value="malwagon")
        misp_object.add_attribute("permalink", type="link", value=self.client.report_url(scan_id))
        score = summary.get("score")
        if isinstance(score, (int, float)):
            misp_object.add_attribute("score", type="text", value=str(score))
        for line in self._result_lines(summary):
            misp_object.add_attribute("results", type="text", value=line, disable_correlation=True)
        if self.attribute_uuid:
            misp_object.add_reference(self.attribute_uuid, "related-to")
        self.misp_event.add_object(misp_object)
        return misp_object

    @staticmethod
    def _verdict_attribute(report):
        for attribute in report.attributes:
            if attribute.object_relation == "results" and attribute.value.startswith("verdict:"):
                return attribute
        return None

    @staticmethod
    def _result_lines(summary):
        lines = []
        if summary.get("verdict"):
            # First, so _verdict_attribute finds it and so an analyst reading the
            # object sees the conclusion before the metadata.
            lines.append(f"verdict: {clean_text(summary['verdict'])}")
        for key in ("status", "module", "submitted_at", "finished_at"):
            if summary.get(key):
                lines.append(f"{key}: {clean_text(summary[key])}")
        tags = summary.get("tags")
        if isinstance(tags, list) and tags:
            # Reported as text on purpose. Turning a remote string into a MISP
            # tag would let the service write into the instance's taxonomies.
            joined = ", ".join(clean_text(tag) for tag in tags[:MAX_TAGS])
            lines.append(f"tags: {joined}")
        return lines

    @staticmethod
    def _tag(attribute, verdict):
        tags = VERDICT_TAGS.get(str(verdict or "").lower())
        if not tags:
            return False
        for tag in tags:
            attribute.add_tag(tag)
        return True

    def get_results(self, empty_message):
        event = self.misp_event.to_dict()
        results = {key: event[key] for key in ("Attribute", "Object") if event.get(key)}
        if not results:
            return {"error": empty_message}
        return {"results": results}
