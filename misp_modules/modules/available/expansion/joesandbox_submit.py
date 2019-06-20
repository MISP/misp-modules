import jbxapi
import base64
import io
import json
import logging
import sys
import zipfile
import re

from urllib.parse import urljoin


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
sh.setFormatter(fmt)
log.addHandler(sh)

moduleinfo = {
    "version": "1.0",
    "author": "Joe Security LLC",
    "description": "Submit files and URLs to Joe Sandbox",
    "module-type": ["expansion", "hover"]
}
moduleconfig = [
    "apiurl",
    "apikey",
    "accept-tac",
    "report-cache",
    "systems",
]

mispattributes = {
    "input": ["attachment", "malware-sample", "url", "domain"],
    "output": ["link"],
}


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    apiurl = request["config"].get("apiurl") or "https://jbxcloud.joesecurity.org/api"
    apikey = request["config"].get("apikey")

    # systems
    systems = request["config"].get("systems") or ""
    systems = [s.strip() for s in re.split(r"[\s,;]", systems) if s.strip()]

    try:
        accept_tac = _parse_bool(request["config"].get("accept-tac"), "accept-tac")
        report_cache = _parse_bool(request["config"].get("report-cache"), "report-cache")
    except _ParseError as e:
        return {"error": str(e)}

    params = {
        "report-cache": report_cache,
        "systems": systems,
    }

    if not apikey:
        return {"error": "No API key provided"}

    joe = jbxapi.JoeSandbox(apiurl=apiurl, apikey=apikey, user_agent="MISP joesandbox_submit", accept_tac=accept_tac)

    try:
        is_url_submission = "url" in request or "domain" in request

        if is_url_submission:
            url = request.get("url") or request.get("domain")

            log.info("Submitting URL: %s", url)
            result = joe.submit_url(url, params=params)
        else:
            if "malware-sample" in request:
                filename = request.get("malware-sample").split("|", 1)[0]
                data = _decode_malware(request["data"], True)
            elif "attachment" in request:
                filename = request["attachment"]
                data = _decode_malware(request["data"], False)

            data_fp = io.BytesIO(data)
            log.info("Submitting sample: %s", filename)
            result = joe.submit_sample((filename, data_fp), params=params)

        assert "submission_id" in result
    except jbxapi.JoeException as e:
        return {"error": str(e)}

    link_to_analysis = urljoin(apiurl, "../submissions/{}".format(result["submission_id"]))

    return {
        "results": [{
            "types": "link",
            "categories": "External analysis",
            "values": link_to_analysis,
        }]
    }


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _decode_malware(data, is_encrypted):
    data = base64.b64decode(data)

    if is_encrypted:
        with zipfile.ZipFile(io.BytesIO(data)) as zipf:
            data = zipf.read(zipf.namelist()[0], pwd=b"infected")

    return data


class _ParseError(Exception):
    pass


def _parse_bool(value, name="bool"):
    if value is None or value == "":
        return None

    if value == "true":
        return True

    if value == "false":
        return False

    raise _ParseError("Cannot parse {}. Must be 'true' or 'false'".format(name))
