#!/usr/bin/env python3

"""
Cytomic Orion MISP Module
An expansion module to enrich attributes in MISP and share indicators of compromise with Cytomic Orion


"""

import json
import sys

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.3",
    "author": "Koen Van Impe",
    "description": "An expansion module to enrich attributes in MISP by quering the Cytomic Orion API",
    "module-type": ["expansion"],
    "name": "Cytomic Orion Lookup",
    "logo": "cytomic_orion.png",
    "requirements": ["Access (license) to Cytomic Orion"],
    "features": (
        "This module takes an MD5 hash and searches for occurrences of this hash in the Cytomic Orion database. Returns"
        " observed files and machines."
    ),
    "references": [
        "https://www.vanimpe.eu/2020/03/10/integrating-misp-and-cytomic-orion/",
        "https://www.cytomicmodel.com/solutions/",
    ],
    "input": "MD5, hash of the sample / malware to search for.",
    "output": "MISP objects with sightings of the hash in Cytomic Orion. Includes files and machines.",
}
moduleconfig = [
    "api_url",
    "token_url",
    "clientid",
    "clientsecret",
    "clientsecret",
    "username",
    "password",
    "upload_timeframe",
    "upload_tag",
    "delete_tag",
    "upload_ttlDays",
    "upload_threat_level_id",
    "limit_upload_events",
    "limit_upload_attributes",
]
# There are more config settings in this module than used by the enrichment
# There is also a PyMISP module which reuses the module config, and requires additional configuration, for example used for pushing indicators to the API


class CytomicParser:
    def __init__(self, attribute, config_object):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)

        self.config_object = config_object

        if self.config_object:
            self.token = self.get_token()
        else:
            sys.exit("Missing configuration")

    def get_token(self):
        try:
            scope = self.config_object["scope"]
            grant_type = self.config_object["grant_type"]
            username = self.config_object["username"]
            password = self.config_object["password"]
            token_url = self.config_object["token_url"]
            clientid = self.config_object["clientid"]
            clientsecret = self.config_object["clientsecret"]

            if scope and grant_type and username and password:
                data = {
                    "scope": scope,
                    "grant_type": grant_type,
                    "username": username,
                    "password": password,
                }

                if token_url and clientid and clientsecret:
                    access_token_response = requests.post(
                        token_url,
                        data=data,
                        verify=False,
                        allow_redirects=False,
                        auth=(clientid, clientsecret),
                    )
                    tokens = json.loads(access_token_response.text)
                    if "access_token" in tokens:
                        return tokens["access_token"]
                    else:
                        self.result = {"error": "No token received."}
                        return
                else:
                    self.result = {"error": "No token_url, clientid or clientsecret supplied."}
                    return
            else:
                self.result = {"error": "No scope, grant_type, username or password supplied."}
                return
        except Exception:
            self.result = {"error": "Unable to connect to token_url."}
            return

    def get_results(self):
        if hasattr(self, "result"):
            return self.result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}

    def parse(self, searchkey):

        if self.token:

            endpoint_fileinformation = self.config_object["endpoint_fileinformation"]
            endpoint_machines = self.config_object["endpoint_machines"]
            endpoint_machines_client = self.config_object["endpoint_machines_client"]
            query_machines = self.config_object["query_machines"]
            query_machine_info = self.config_object["query_machine_info"]

            # Update endpoint URLs
            query_endpoint_fileinformation = endpoint_fileinformation.format(md5=searchkey)
            query_endpoint_machines = endpoint_machines.format(md5=searchkey)

            # API calls
            api_call_headers = {"Authorization": "Bearer " + self.token}
            result_query_endpoint_fileinformation = requests.get(
                query_endpoint_fileinformation, headers=api_call_headers, verify=False
            )
            json_result_query_endpoint_fileinformation = json.loads(result_query_endpoint_fileinformation.text)

            if json_result_query_endpoint_fileinformation:

                cytomic_object = MISPObject("cytomic-orion-file")

                cytomic_object.add_attribute(
                    "fileName",
                    type="text",
                    value=json_result_query_endpoint_fileinformation["fileName"],
                )
                cytomic_object.add_attribute(
                    "fileSize",
                    type="text",
                    value=json_result_query_endpoint_fileinformation["fileSize"],
                )
                cytomic_object.add_attribute(
                    "last-seen",
                    type="datetime",
                    value=json_result_query_endpoint_fileinformation["lastSeen"],
                )
                cytomic_object.add_attribute(
                    "first-seen",
                    type="datetime",
                    value=json_result_query_endpoint_fileinformation["firstSeen"],
                )
                cytomic_object.add_attribute(
                    "classification",
                    type="text",
                    value=json_result_query_endpoint_fileinformation["classification"],
                )
                cytomic_object.add_attribute(
                    "classificationName",
                    type="text",
                    value=json_result_query_endpoint_fileinformation["classificationName"],
                )
                self.misp_event.add_object(**cytomic_object)

                result_query_endpoint_machines = requests.get(
                    query_endpoint_machines, headers=api_call_headers, verify=False
                )
                json_result_query_endpoint_machines = json.loads(result_query_endpoint_machines.text)

                if (
                    query_machines
                    and json_result_query_endpoint_machines
                    and len(json_result_query_endpoint_machines) > 0
                ):
                    for machine in json_result_query_endpoint_machines:

                        if query_machine_info and machine["muid"]:
                            query_endpoint_machines_client = endpoint_machines_client.format(muid=machine["muid"])
                            result_endpoint_machines_client = requests.get(
                                query_endpoint_machines_client,
                                headers=api_call_headers,
                                verify=False,
                            )
                            json_result_endpoint_machines_client = json.loads(result_endpoint_machines_client.text)

                            if json_result_endpoint_machines_client:

                                cytomic_machine_object = MISPObject("cytomic-orion-machine")

                                clienttag = [{"name": json_result_endpoint_machines_client["clientName"]}]

                                cytomic_machine_object.add_attribute(
                                    "machineName",
                                    type="target-machine",
                                    value=json_result_endpoint_machines_client["machineName"],
                                    Tag=clienttag,
                                )
                                cytomic_machine_object.add_attribute("machineMuid", type="text", value=machine["muid"])
                                cytomic_machine_object.add_attribute(
                                    "clientName",
                                    type="target-org",
                                    value=json_result_endpoint_machines_client["clientName"],
                                    Tag=clienttag,
                                )
                                cytomic_machine_object.add_attribute("clientId", type="text", value=machine["clientId"])
                                cytomic_machine_object.add_attribute(
                                    "machinePath",
                                    type="text",
                                    value=machine["lastPath"],
                                )
                                cytomic_machine_object.add_attribute(
                                    "first-seen",
                                    type="datetime",
                                    value=machine["firstSeen"],
                                )
                                cytomic_machine_object.add_attribute(
                                    "last-seen",
                                    type="datetime",
                                    value=machine["lastSeen"],
                                )
                                cytomic_machine_object.add_attribute(
                                    "creationDate",
                                    type="datetime",
                                    value=json_result_endpoint_machines_client["creationDate"],
                                )
                                cytomic_machine_object.add_attribute(
                                    "clientCreationDateUTC",
                                    type="datetime",
                                    value=json_result_endpoint_machines_client["clientCreationDateUTC"],
                                )
                                cytomic_machine_object.add_attribute(
                                    "lastSeenUtc",
                                    type="datetime",
                                    value=json_result_endpoint_machines_client["lastSeenUtc"],
                                )
                                self.misp_event.add_object(**cytomic_machine_object)
        else:
            self.result = {"error": "No (valid) token."}
            return


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("attribute"):
        return {"error": "Unsupported input."}

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if not any(input_type == attribute["type"] for input_type in mispattributes["input"]):
        return {"error": "Unsupported attribute type."}

    if not request.get("config"):
        return {"error": "Missing configuration"}

    config_object = {
        "clientid": request["config"].get("clientid"),
        "clientsecret": request["config"].get("clientsecret"),
        "scope": "orion.api",
        "password": request["config"].get("password"),
        "username": request["config"].get("username"),
        "grant_type": "password",
        "token_url": request["config"].get("token_url"),
        "endpoint_fileinformation": "{api_url}{endpoint}".format(
            api_url=request["config"].get("api_url"),
            endpoint="/forensics/md5/{md5}/info",
        ),
        "endpoint_machines": "{api_url}{endpoint}".format(
            api_url=request["config"].get("api_url"),
            endpoint="/forensics/md5/{md5}/muids",
        ),
        "endpoint_machines_client": "{api_url}{endpoint}".format(
            api_url=request["config"].get("api_url"),
            endpoint="/forensics/muid/{muid}/info",
        ),
        "query_machines": True,
        "query_machine_info": True,
    }

    cytomic_parser = CytomicParser(attribute, config_object)
    cytomic_parser.parse(attribute["value"])

    return cytomic_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
