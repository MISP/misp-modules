#!/usr/bin/env python3

# Copyright 2022 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Creates a VT Collection with indicators present in a given event."""

import base64
import json

import requests

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["hostname", "domain", "ip-src", "ip-dst", "md5", "sha1", "sha256", "url"],
    "format": "misp_standard",
    "responseType": "application/txt",
    "outputFileExtension": "txt",
}

moduleinfo = {
    "version": "1.0",
    "author": "VirusTotal",
    "description": "Creates a VT Collection from an event iocs.",
    "module-type": ["export"],
    "name": "VirusTotal Collections Export",
    "logo": "virustotal.png",
    "requirements": ["An access to the VirusTotal API (apikey)."],
    "features": (
        "This export module which takes advantage of a new endpoint in VT APIv3 to create VT Collections from IOCs"
        " contained in a MISP event. With this module users will be able to create a collection just using the Download"
        " as... button."
    ),
    "references": [
        "https://www.virustotal.com/",
        "https://blog.virustotal.com/2021/11/introducing-virustotal-collections.html",
    ],
    "input": "A domain, hash (md5, sha1, sha256 or sha512), hostname, url or IP address attribute.",
    "output": "A VirusTotal collection in VT.",
}

moduleconfig = [
    "vt_api_key",
    "proxy_host",
    "proxy_port",
    "proxy_username",
    "proxy_password",
]


class VTError(Exception):
    "Exception class to map vt api response errors."

    pass


def create_collection(api_key, event_data):
    headers = {
        "x-apikey": api_key,
        "content-type": "application/json",
        "x-tool": "MISPModuleVirusTotalCollectionExport",
    }

    response = requests.post(
        "https://www.virustotal.com/api/v3/integrations/misp/collections",
        headers=headers,
        json=event_data,
    )

    uuid = event_data["Event"]["uuid"]
    response_data = response.json()

    if response.status_code == 200:
        col_id = response_data["data"]["id"]
        return f"{uuid}: https://www.virustotal.com/gui/collection/{col_id}/iocs"

    error = response_data["error"]["message"]
    if response.status_code == 400:
        return f"{uuid}: {error}"
    else:
        misperrors["error"] = error
        raise VTError(error)


def normalize_misp_data(data):
    normalized_data = {"Event": data.pop("Event", {})}
    for attr_key in data:
        if isinstance(data[attr_key], list) or isinstance(data[attr_key], dict):
            if attr_key == "EventTag":
                normalized_data["Event"]["Tag"] = [tag["Tag"] for tag in data[attr_key]]
            else:
                normalized_data["Event"][attr_key] = data[attr_key]

    return normalized_data


def handler(q=False):
    request = json.loads(q)

    if not request.get("config") or not request["config"].get("vt_api_key"):
        misperrors["error"] = "A VirusTotal api key is required for this module."
        return misperrors

    config = request["config"]
    data = request["data"]
    responses = []

    try:
        for event_data in data:
            normalized_event = normalize_misp_data(event_data)
            responses.append(create_collection(config.get("vt_api_key"), normalized_event))

        output = "\n".join(responses)
        return {
            "response": [],
            "data": str(base64.b64encode(bytes(output, "utf-8")), "utf-8"),
        }
    except VTError:
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
