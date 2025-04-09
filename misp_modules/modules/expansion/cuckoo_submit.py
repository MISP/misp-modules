import base64
import io
import json
import logging
import sys
import urllib.parse
import zipfile

import requests
from requests.exceptions import RequestException

log = logging.getLogger("cuckoo_submit")
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
sh.setFormatter(fmt)
log.addHandler(sh)

moduleinfo = {
    "version": "0.1",
    "author": "Evert Kors",
    "description": "Submit files and URLs to Cuckoo Sandbox",
    "module-type": ["expansion", "hover"],
    "name": "Cuckoo Submit",
    "logo": "cuckoo.png",
    "requirements": ["Access to a Cuckoo Sandbox API and an API key if the API requires it. (api_url and api_key)"],
    "features": (
        "The module takes a malware-sample, attachment, url or domain and submits it to Cuckoo Sandbox.\n The returned"
        " task id can be used to retrieve results when the analysis completed."
    ),
    "references": ["https://cuckoosandbox.org/", "https://cuckoo.sh/docs/"],
    "input": "A malware-sample or attachment for files. A url or domain for URLs.",
    "output": "A text field containing 'Cuckoo task id: <id>'",
}
misperrors = {"error": "Error"}
moduleconfig = ["api_url", "api_key"]
mispattributes = {
    "input": ["attachment", "malware-sample", "url", "domain"],
    "output": ["text"],
}


class APIKeyError(RequestException):
    """Raised if the Cuckoo API returns a 401. This means no or an invalid
    bearer token was supplied."""

    pass


class CuckooAPI(object):

    def __init__(self, api_url, api_key=""):
        self.api_key = api_key
        if not api_url.startswith("http"):
            api_url = "https://{}".format(api_url)

        self.api_url = api_url

    def _post_api(self, endpoint, files=None, data={}):
        data.update({"owner": "MISP"})

        try:
            response = requests.post(
                urllib.parse.urljoin(self.api_url, endpoint),
                files=files,
                data=data,
                headers={"Authorization": "Bearer {}".format(self.api_key)},
            )
        except RequestException as e:
            log.error("Failed to submit sample to Cuckoo Sandbox. %s", e)
            return None

        if response.status_code == 401:
            raise APIKeyError("Invalid or no Cuckoo Sandbox API key provided")

        if response.status_code != 200:
            log.error("Invalid Cuckoo API response")
            return None

        return response.json()

    def create_task(self, filename, fp):
        response = self._post_api("/tasks/create/file", files={"file": (filename, fp)})
        if not response:
            return False

        return response["task_id"]

    def create_url(self, url):
        response = self._post_api("/tasks/create/url", data={"url": url})
        if not response:
            return False

        return response["task_id"]


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    # See if the API URL was provided. The API key is optional, as it can
    # be disabled in the Cuckoo API settings.
    api_url = request["config"].get("api_url")
    api_key = request["config"].get("api_key", "")
    if not api_url:
        misperrors["error"] = "No Cuckoo API URL provided"
        return misperrors

    url = request.get("url") or request.get("domain")
    data = request.get("data")
    filename = None
    if data:
        data = base64.b64decode(data)

        if "malware-sample" in request:
            filename = request.get("malware-sample").split("|", 1)[0]
            with zipfile.ZipFile(io.BytesIO(data)) as zipf:
                data = zipf.read(zipf.namelist()[0], pwd=b"infected")

        elif "attachment" in request:
            filename = request.get("attachment")

    cuckoo_api = CuckooAPI(api_url=api_url, api_key=api_key)
    task_id = None
    try:
        if url:
            log.debug("Submitting URL to Cuckoo Sandbox %s", api_url)
            task_id = cuckoo_api.create_url(url)
        elif data and filename:
            log.debug("Submitting file to Cuckoo Sandbox %s", api_url)
            task_id = cuckoo_api.create_task(filename=filename, fp=io.BytesIO(data))
    except APIKeyError as e:
        misperrors["error"] = "Failed to submit to Cuckoo: {}".format(e)
        return misperrors

    if not task_id:
        misperrors["error"] = "File or URL submission failed"
        return misperrors

    return {"results": [{"types": "text", "values": "Cuckoo task id: {}".format(task_id)}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
