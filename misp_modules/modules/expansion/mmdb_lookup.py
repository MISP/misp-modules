import json

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-src|port", "ip-dst", "ip-dst|port"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1",
    "author": "Jeroen Pinoy",
    "description": (
        "A hover and expansion module to enrich an ip with geolocation and ASN information from an mmdb server"
        " instance, such as CIRCL's ip.circl.lu."
    ),
    "module-type": ["expansion", "hover"],
    "name": "GeoIP Enrichment",
    "logo": "circl.png",
    "requirements": [],
    "features": (
        "The module takes an IP address related attribute as input.\n It queries the public CIRCL.lu mmdb-server"
        " instance, available at ip.circl.lu, by default. The module can be configured with a custom mmdb server url if"
        " required.\n It is also possible to filter results on 1 db_source by configuring db_source_filter."
    ),
    "references": [
        "https://data.public.lu/fr/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/",
        "https://github.com/adulau/mmdb-server",
    ],
    "input": "An IP address attribute (for example ip-src or ip-src|port).",
    "output": "Geolocation and asn objects.",
}
moduleconfig = ["custom_API", "db_source_filter", "max_country_info_qt"]
mmdblookup_url = "https://ip.circl.lu/"


class MmdbLookupParser:
    def __init__(self, attribute, mmdblookupresult, api_url, max_country_info_qt=0):
        self.attribute = attribute
        self.mmdblookupresult = mmdblookupresult
        self.api_url = api_url
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.max_country_info_qt = int(max_country_info_qt)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def parse_mmdblookup_information(self):
        # There is a chance some db's have a hit while others don't so we have to check if entry is empty each time
        country_info_qt = 0
        for result_entry in self.mmdblookupresult:
            if result_entry["country_info"]:
                if (self.max_country_info_qt == 0) or (
                    self.max_country_info_qt > 0 and country_info_qt < self.max_country_info_qt
                ):
                    mmdblookup_object = MISPObject("geolocation")
                    mmdblookup_object.add_attribute(
                        "country",
                        **{
                            "type": "text",
                            "value": result_entry["country_info"]["Country"],
                        },
                    )
                    mmdblookup_object.add_attribute(
                        "countrycode",
                        **{
                            "type": "text",
                            "value": result_entry["country"]["iso_code"],
                        },
                    )
                    mmdblookup_object.add_attribute(
                        "latitude",
                        **{
                            "type": "float",
                            "value": result_entry["country_info"]["Latitude (average)"],
                        },
                    )
                    mmdblookup_object.add_attribute(
                        "longitude",
                        **{
                            "type": "float",
                            "value": result_entry["country_info"]["Longitude (average)"],
                        },
                    )
                    mmdblookup_object.add_attribute(
                        "text",
                        **{
                            "type": "text",
                            "value": "db_source: {}. build_db: {}. Latitude and longitude are country average.".format(
                                result_entry["meta"]["db_source"],
                                result_entry["meta"]["build_db"],
                            ),
                        },
                    )
                    mmdblookup_object.add_reference(self.attribute["uuid"], "related-to")
                    self.misp_event.add_object(mmdblookup_object)
                    country_info_qt += 1
                if "AutonomousSystemNumber" in result_entry["country"]:
                    mmdblookup_object_asn = MISPObject("asn")
                    mmdblookup_object_asn.add_attribute(
                        "asn",
                        **{
                            "type": "text",
                            "value": result_entry["country"]["AutonomousSystemNumber"],
                        },
                    )
                    mmdblookup_object_asn.add_attribute(
                        "description",
                        **{
                            "type": "text",
                            "value": "ASNOrganization: {}. db_source: {}. build_db: {}.".format(
                                result_entry["country"]["AutonomousSystemOrganization"],
                                result_entry["meta"]["db_source"],
                                result_entry["meta"]["build_db"],
                            ),
                        },
                    )
                    mmdblookup_object_asn.add_reference(self.attribute["uuid"], "related-to")
                    self.misp_event.add_object(mmdblookup_object_asn)


def check_url(url):
    return "{}/".format(url) if not url.endswith("/") else url


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") == "ip-src":
        toquery = attribute["value"]
    elif attribute.get("type") == "ip-src|port":
        toquery = attribute["value"].split("|")[0]
    elif attribute.get("type") == "ip-dst":
        toquery = attribute["value"]
    elif attribute.get("type") == "ip-dst|port":
        toquery = attribute["value"].split("|")[0]
    else:
        misperrors["error"] = "There is no attribute of type ip-src or ip-dst provided as input"
        return misperrors
    max_country_info_qt = request["config"].get("max_country_info_qt", 0)
    if max_country_info_qt is None:
        max_country_info_qt = 0
    api_url = (
        check_url(request["config"]["custom_API"])
        if "config" in request and request["config"].get("custom_API")
        else mmdblookup_url
    )
    r = requests.get("{}/geolookup/{}".format(api_url, toquery))
    if r.status_code == 200:
        mmdblookupresult = r.json()
        if not mmdblookupresult or len(mmdblookupresult) == 0:
            misperrors["error"] = "Empty result returned by server"
            return misperrors
        if "config" in request and request["config"].get("db_source_filter"):
            db_source_filter = request["config"].get("db_source_filter")
            mmdblookupresult = [entry for entry in mmdblookupresult if entry["meta"]["db_source"] == db_source_filter]
            if not mmdblookupresult or len(mmdblookupresult) == 0:
                misperrors["error"] = "There was no result with the selected db_source"
                return misperrors
        # Server might return one or multiple entries which could all be empty, we check if there is at least one
        # non-empty result below
        empty_result = True
        for lookup_result_entry in mmdblookupresult:
            if lookup_result_entry["country_info"]:
                empty_result = False
                break
        if empty_result:
            misperrors["error"] = "Empty result returned by server"
            return misperrors
    else:
        misperrors["error"] = "API not accessible - http status code {} was returned".format(r.status_code)
        return misperrors
    parser = MmdbLookupParser(attribute, mmdblookupresult, api_url, max_country_info_qt)
    parser.parse_mmdblookup_information()
    result = parser.get_result()
    return result


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
