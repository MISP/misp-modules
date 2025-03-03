import base64
import hashlib
import io
import json
import re
import zipfile

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment", "malware-sample"], "output": ["link"]}
moduleinfo = {
    "version": "1",
    "author": "Karen Yousefi",
    "description": "Module to push malware samples to MalShare",
    "module-type": ["expansion"],
    "name": "MalShare Upload",
    "requirements": ["requests library"],
    "logo": "",
}

moduleconfig = ["malshare_apikey"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    try:
        data = request.get("data")
        if "malware-sample" in request:
            sample_filename = request.get("malware-sample").split("|", 1)[0]
            data = base64.b64decode(data)
            fl = io.BytesIO(data)
            zf = zipfile.ZipFile(fl)
            sample_hashname = zf.namelist()[0]
            data = zf.read(sample_hashname, b"infected")
            zf.close()
        elif "attachment" in request:
            sample_filename = request.get("attachment")
            data = base64.b64decode(data)
        else:
            misperrors["error"] = "No malware sample or attachment supplied"
            return misperrors
    except Exception:
        misperrors["error"] = "Unable to process submitted sample data"
        return misperrors

    if request["config"].get("malshare_apikey") is None:
        misperrors["error"] = "Missing MalShare API key"
        return misperrors

    malshare_apikey = request["config"].get("malshare_apikey")

    try:
        url = "https://malshare.com/api.php"
        params = {"api_key": malshare_apikey, "action": "upload"}
        files = {"upload": (sample_filename, data)}
        response = requests.post(url, params=params, files=files)
        response.raise_for_status()

        response_text = response.text.strip()

        # Calculate SHA256 of the file
        sha256 = hashlib.sha256(data).hexdigest()

        if response_text.startswith("Success"):
            # If upload was successful or file already exists
            malshare_link = f"https://malshare.com/sample.php?action=detail&hash={sha256}"
        elif "sample already exists" in response_text:
            # If file already exists, extract SHA256 from response
            match = re.search(r"([a-fA-F0-9]{64})", response_text)
            if match:
                sha256 = match.group(1)
            malshare_link = f"https://malshare.com/sample.php?action=detail&hash={sha256}"
        else:
            # If there's any other error
            raise Exception(f"Upload failed: {response_text}")

    except Exception as e:
        misperrors["error"] = f"Unable to send sample to MalShare: {str(e)}"
        return misperrors

    r = {
        "results": [
            {
                "types": "link",
                "values": malshare_link,
                "comment": "Link to MalShare analysis",
            }
        ]
    }
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
