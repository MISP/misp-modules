# Written by mohlcyber 13.08.2021
# MISP Module for McAfee MVISION Insights to query campaign details

import json
import logging
import sys

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256"], "format": "misp_standard"}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Martin Ohl",
    "description": "Lookup McAfee MVISION Insights Details",
    "module-type": ["hover"],
    "name": "McAfee MVISION Insights Lookup",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

# config fields that your code expects from the site admin
moduleconfig = ["api_key", "client_id", "client_secret"]


class MVAPI:
    def __init__(self, attribute, api_key, client_id, client_secret):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)

        self.base_url = "https://api.mvision.mcafee.com"
        self.session = requests.Session()

        self.api_key = api_key
        auth = (client_id, client_secret)

        self.logging()
        self.auth(auth)

    def logging(self):
        self.logger = logging.getLogger("logs")
        self.logger.setLevel("INFO")
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def auth(self, auth):
        iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token"

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/vnd.api+json",
        }

        payload = {
            "grant_type": "client_credentials",
            "scope": "ins.user ins.suser ins.ms.r",
        }

        res = self.session.post(iam_url, headers=headers, auth=auth, data=payload)

        if res.status_code != 200:
            self.logger.error(
                "Could not authenticate to get the IAM token: {0} - {1}".format(res.status_code, res.text)
            )
            sys.exit()
        else:
            self.logger.info("Successful authenticated.")
            access_token = res.json()["access_token"]
            headers["Authorization"] = "Bearer " + access_token
            self.session.headers = headers

    def search_ioc(self):
        filters = {
            "filter[type][eq]": self.attribute.type,
            "filter[value]": self.attribute.value,
            "fields": (
                "id, type, value, coverage, uid, is_coat, is_sdb_dirty, category, comment, campaigns, threat,"
                " prevalence"
            ),
        }
        res = self.session.get(self.base_url + "/insights/v2/iocs", params=filters)

        if res.ok:
            if len(res.json()["data"]) == 0:
                self.logger.info("No Hash details in MVISION Insights found.")
            else:
                self.logger.info("Successfully retrieved MVISION Insights details.")
                self.logger.debug(res.text)
                return res.json()
        else:
            self.logger.error("Error in search_ioc. HTTP {0} - {1}".format(str(res.status_code), res.text))
            sys.exit()

    def prep_result(self, ioc):
        res = ioc["data"][0]
        results = []

        # Parse out Attribute Category
        category_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Attribute Category: {0}".format(res["attributes"]["category"]),
        }
        results.append(category_attr)

        # Parse out Attribute Comment
        comment_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Attribute Comment: {0}".format(res["attributes"]["comment"]),
        }
        results.append(comment_attr)

        # Parse out Attribute Dat Coverage
        cover_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Dat Version Coverage: {0}".format(res["attributes"]["coverage"]["dat_version"]["min"]),
        }
        results.append(cover_attr)

        # Parse out if Dirty
        cover_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Is Dirty: {0}".format(res["attributes"]["is-sdb-dirty"]),
        }
        results.append(cover_attr)

        # Parse our targeted countries
        countries_dict = []
        countries = res["attributes"]["prevalence"]["countries"]

        for country in countries:
            countries_dict.append(country["iso_code"])

        country_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Targeted Countries: {0}".format(countries_dict),
        }
        results.append(country_attr)

        # Parse out targeted sectors
        sectors_dict = []
        sectors = res["attributes"]["prevalence"]["sectors"]

        for sector in sectors:
            sectors_dict.append(sector["sector"])

        sector_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Targeted Sectors: {0}".format(sectors_dict),
        }
        results.append(sector_attr)

        # Parse out Threat Classification
        threat_class_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Threat Classification: {0}".format(res["attributes"]["threat"]["classification"]),
        }
        results.append(threat_class_attr)

        # Parse out Threat Name
        threat_name_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Threat Name: {0}".format(res["attributes"]["threat"]["name"]),
        }
        results.append(threat_name_attr)

        # Parse out Threat Severity
        threat_sev_attr = {
            "type": "text",
            "object_relation": "text",
            "value": "Threat Severity: {0}".format(res["attributes"]["threat"]["severity"]),
        }
        results.append(threat_sev_attr)

        # Parse out Attribute ID
        attr_id = {
            "type": "text",
            "object_relation": "text",
            "value": "Attribute ID: {0}".format(res["id"]),
        }
        results.append(attr_id)

        # Parse out Campaign Relationships
        campaigns = ioc["included"]

        for campaign in campaigns:
            campaign_attr = {
                "type": "campaign-name",
                "object_relation": "campaign-name",
                "value": campaign["attributes"]["name"],
            }
            results.append(campaign_attr)

        mv_insights_obj = MISPObject(name="MVISION Insights Details")
        for mvi_res in results:
            mv_insights_obj.add_attribute(**mvi_res)
        mv_insights_obj.add_reference(self.attribute.uuid, "mvision-insights-details")

        self.misp_event.add_object(mv_insights_obj)

        event = json.loads(self.misp_event.to_json())
        results_mvi = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}

        return {"results": results_mvi}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if (
        not request.get("config")
        or not request["config"].get("api_key")
        or not request["config"].get("client_id")
        or not request["config"].get("client_secret")
    ):
        misperrors["error"] = "Please provide MVISION API Key, Client ID and Client Secret."
        return misperrors
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type. Please use {0}".format(mispattributes["input"])}

    api_key = request["config"]["api_key"]
    client_id = request["config"]["client_id"]
    client_secret = request["config"]["client_secret"]
    attribute = request["attribute"]

    mvi = MVAPI(attribute, api_key, client_id, client_secret)
    res = mvi.search_ioc()
    return mvi.prep_result(res)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
