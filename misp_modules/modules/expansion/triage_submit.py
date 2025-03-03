import base64
import io
import json
import zipfile

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["attachment", "malware-sample", "url"], "output": ["link"]}
moduleinfo = {
    "version": "1",
    "author": "Karen Yousefi",
    "description": "Module to submit samples to tria.ge",
    "module-type": ["expansion", "hover"],
    "name": "Triage Submit",
    "logo": "",
}

moduleconfig = ["apikey", "url_mode"]


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if request.get("config", {}).get("apikey") is None:
        misperrors["error"] = "tria.ge API key is missing"
        return misperrors

    api_key = request["config"]["apikey"]
    url_mode = request["config"].get("url_mode", "submit")  # 'submit' or 'fetch'
    base_url = "https://tria.ge/api/v0/samples"
    headers = {"Authorization": f"Bearer {api_key}"}

    if "attachment" in request:
        data = request["data"]
        filename = request["attachment"]
        return submit_file(headers, base_url, data, filename)
    elif "malware-sample" in request:
        data = request["data"]
        filename = request["malware-sample"].split("|")[0]
        return submit_file(headers, base_url, data, filename, is_malware_sample=True)
    elif "url" in request:
        url = request["url"]
        return submit_url(headers, base_url, url, url_mode)
    else:
        misperrors["error"] = "Unsupported input type"
        return misperrors


def submit_file(headers, base_url, data, filename, is_malware_sample=False):
    try:
        if is_malware_sample:
            file_data = base64.b64decode(data)
            zip_file = zipfile.ZipFile(io.BytesIO(file_data))
            file_data = zip_file.read(zip_file.namelist()[0], pwd=b"infected")
        else:
            file_data = base64.b64decode(data)

        files = {"file": (filename, file_data)}
        response = requests.post(base_url, headers=headers, files=files)
        response.raise_for_status()
        result = response.json()

        sample_id = result["id"]
        sample_url = f"https://tria.ge/{sample_id}"

        return {
            "results": [
                {
                    "types": "link",
                    "values": sample_url,
                    "comment": "Link to tria.ge analysis",
                }
            ]
        }

    except Exception as e:
        misperrors["error"] = f"Error submitting to tria.ge: {str(e)}"
        return misperrors


def submit_url(headers, base_url, url, mode):
    try:
        if mode == "fetch":
            data = {"kind": "fetch", "url": url}
        else:  # submit
            data = {"kind": "url", "url": url}

        response = requests.post(base_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()

        sample_id = result["id"]
        sample_url = f"https://tria.ge/{sample_id}"

        return {
            "results": [
                {
                    "types": "link",
                    "values": sample_url,
                    "comment": f"Link to tria.ge analysis ({mode} mode)",
                }
            ]
        }

    except Exception as e:
        misperrors["error"] = f"Error submitting to tria.ge: {str(e)}"
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
