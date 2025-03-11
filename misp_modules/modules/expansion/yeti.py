import json
import logging

import pyeti
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}

mispattributes = {
    "input": [
        "AS",
        "ip-src",
        "ip-dst",
        "hostname",
        "domain",
        "sha256",
        "sha1",
        "md5",
        "url",
    ],
    "format": "misp_standard",
}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a query on Yeti.",
    "module-type": ["expansion", "hover"],
    "name": "Yeti Lookup",
    "logo": "yeti.png",
    "requirements": ["pyeti", "API key "],
    "features": "This module add context and links between observables using yeti",
    "references": [
        "https://github.com/yeti-platform/yeti",
        "https://github.com/sebdraven/pyeti",
    ],
    "input": "A domain, hostname,IP, sha256,sha1, md5, url of MISP attribute.",
    "output": "MISP attributes and objects fetched from the Yeti instances.",
}

moduleconfig = ["apikey", "url"]


class Yeti:

    def __init__(self, url, key, attribute):
        self.misp_mapping = {
            "Ip": "ip-dst",
            "Domain": "domain",
            "Hostname": "hostname",
            "Url": "url",
            "AutonomousSystem": "AS",
            "File": "sha256",
        }
        self.yeti_client = pyeti.YetiApi(url=url, api_key=key)
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    def search(self, value):
        obs = self.yeti_client.observable_search(value=value)
        if obs:
            return obs[0]

    def get_neighboors(self, obs_id):
        neighboors = self.yeti_client.neighbors_observables(obs_id)
        if neighboors and "objs" in neighboors:
            links_by_id = {
                link["dst"]["id"]: (link["description"], "dst")
                for link in neighboors["links"]
                if link["dst"]["id"] != obs_id
            }
            links_by_id.update(
                {
                    link["src"]["id"]: (link["description"], "src")
                    for link in neighboors["links"]
                    if link["src"]["id"] != obs_id
                }
            )

            for n in neighboors["objs"]:
                yield n, links_by_id[n["id"]]

    def parse_yeti_result(self):
        obs = self.search(self.attribute["value"])

        for obs_to_add, link in self.get_neighboors(obs["id"]):
            object_misp_domain_ip = self.__get_object_domain_ip(obs_to_add)
            if object_misp_domain_ip:
                self.misp_event.add_object(object_misp_domain_ip)
                continue
            object_misp_url = self.__get_object_url(obs_to_add)
            if object_misp_url:
                self.misp_event.add_object(object_misp_url)
                continue
            if link[0] == "NS record":
                object_ns_record = self.__get_object_ns_record(obs_to_add, link[1])
                if object_ns_record:
                    self.misp_event.add_object(object_ns_record)
                    continue
            self.__get_attribute(obs_to_add, link[0])

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if key in event}
        return results

    def __get_attribute(self, obs_to_add, link):

        try:
            type_attr = self.misp_mapping[obs_to_add["type"]]
            value = None
            if obs_to_add["type"] == "File":
                value = obs_to_add["value"].split(":")[1]
            else:
                value = obs_to_add["value"]
            attr = self.misp_event.add_attribute(value=value, type=type_attr)
            attr.comment = "%s: %s" % (link, self.attribute["value"])
        except KeyError:
            logging.error("type not found %s" % obs_to_add["type"])
            return

        for t in obs_to_add["tags"]:
            self.misp_event.add_attribute_tag(t["name"], attr["uuid"])

    def __get_object_domain_ip(self, obj_to_add):
        if (obj_to_add["type"] == "Ip" and self.attribute["type"] in ["hostname", "domain"]) or (
            obj_to_add["type"] in ("Hostname", "Domain") and self.attribute["type"] in ("ip-src", "ip-dst")
        ):
            domain_ip_object = MISPObject("domain-ip")
            domain_ip_object.add_attribute(self.__get_relation(obj_to_add), obj_to_add["value"])
            domain_ip_object.add_attribute(
                self.__get_relation(self.attribute, is_yeti_object=False),
                self.attribute["value"],
            )
            domain_ip_object.add_reference(self.attribute["uuid"], "related_to")

            return domain_ip_object

    def __get_object_url(self, obj_to_add):
        if (obj_to_add["type"] == "Url" and self.attribute["type"] in ["hostname", "domain", "ip-src", "ip-dst"]) or (
            obj_to_add["type"] in ("Hostname", "Domain", "Ip") and self.attribute["type"] == "url"
        ):
            url_object = MISPObject("url")
            obj_relation = self.__get_relation(obj_to_add)
            if obj_relation:
                url_object.add_attribute(obj_relation, obj_to_add["value"])
            obj_relation = self.__get_relation(self.attribute, is_yeti_object=False)
            if obj_relation:
                url_object.add_attribute(obj_relation, self.attribute["value"])
            url_object.add_reference(self.attribute["uuid"], "related_to")

            return url_object

    def __get_object_ns_record(self, obj_to_add, link):
        queried_domain = None
        ns_domain = None
        object_dns_record = MISPObject("dns-record")
        if link == "dst":
            queried_domain = self.attribute["value"]
            ns_domain = obj_to_add["value"]
        elif link == "src":
            queried_domain = obj_to_add["value"]
            ns_domain = self.attribute["value"]
        if queried_domain and ns_domain:
            object_dns_record.add_attribute("queried-domain", queried_domain)
            object_dns_record.add_attribute("ns-record", ns_domain)
            object_dns_record.add_reference(self.attribute["uuid"], "related_to")

            return object_dns_record

    def __get_relation(self, obj, is_yeti_object=True):
        if is_yeti_object:
            type_attribute = self.misp_mapping[obj["type"]]
        else:
            type_attribute = obj["type"]
        if type_attribute == "ip-src" or type_attribute == "ip-dst":
            return "ip"
        elif "domain" == type_attribute:
            return "domain"
        elif "hostname" == type_attribute:
            return "domain"
        elif type_attribute == "url":
            return type_attribute


def handler(q=False):
    if q is False:
        return False

    apikey = None
    yeti_url = None
    yeti_client = None

    request = json.loads(q)
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attributes type"}

    if "config" in request and "url" in request["config"]:
        yeti_url = request["config"]["url"]
    if "config" in request and "apikey" in request["config"]:
        apikey = request["config"]["apikey"]
    if apikey and yeti_url:
        yeti_client = Yeti(yeti_url, apikey, attribute)

    if yeti_client:
        yeti_client.parse_yeti_result()
        return {"results": yeti_client.get_result()}
    else:
        misperrors["error"] = "Yeti Config Error"
        return misperrors


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def introspection():
    return mispattributes
