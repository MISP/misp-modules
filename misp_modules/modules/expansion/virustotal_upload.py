import base64
import hashlib
import io
import json
import zipfile

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment", "malware-sample"], "output": ["link"]}
moduleinfo = {
    "version": "1",
    "author": "Karen Yousefi",
    "description": "Module to push malware samples to VirusTotal",
    "module-type": ["expansion"],
    "name": "VirusTotal Upload",
    "requirements": ["requests library"],
    "logo": "virustotal.png",
}

moduleconfig = ["virustotal_apikey"]


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

    if request["config"].get("virustotal_apikey") is None:
        misperrors["error"] = "Missing VirusTotal API key"
        return misperrors

    virustotal_apikey = request["config"].get("virustotal_apikey")

    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "accept": "application/json",
            "x-apikey": virustotal_apikey,
        }
        files = {"file": (sample_filename, data)}
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()

        # Calculate SHA256 of the file
        sha256 = hashlib.sha256(data).hexdigest()

        virustotal_link = f"https://www.virustotal.com/gui/file/{sha256}"
    except Exception as e:
        misperrors["error"] = f"Unable to send sample to VirusTotal: {str(e)}"
        return misperrors

    r = {
        "results": [
            {
                "types": "link",
                "values": virustotal_link,
                "comment": "Link to VirusTotal analysis",
            }
        ]
    }
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
