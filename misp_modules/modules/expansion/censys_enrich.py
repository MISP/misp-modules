# encoding: utf-8
import base64
import codecs
import configparser
import json

import censys.common.config
from dateutil.parser import isoparse
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message


def get_config_over() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config[censys.common.config.DEFAULT] = censys.common.config.default_config
    return config


censys.common.config.get_config = get_config_over
from censys.common.base import CensysException
from censys.search import CensysCertificates, CensysHosts

misperrors = {"error": "Error"}
moduleconfig = ["api_id", "api_secret"]
mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "hostname|port",
        "domain|ip",
        "ip-dst|port",
        "ip-src|port",
        "x509-fingerprint-md5",
        "x509-fingerprint-sha1",
        "x509-fingerprint-sha256",
    ],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "Loïc Fortemps",
    "description": "An expansion module to enrich attributes in MISP by quering the censys.io API",
    "module-type": ["expansion", "hover"],
    "name": "Censys Enrich",
    "logo": "",
    "requirements": ["API credentials to censys.io"],
    "features": (
        "This module takes an IP, hostname or a certificate fingerprint and attempts to enrich it by querying the"
        " Censys API."
    ),
    "references": ["https://www.censys.io"],
    "input": "IP, domain or certificate fingerprint (md5, sha1 or sha256)",
    "output": "MISP objects retrieved from censys, including open ports, ASN, Location of the IP, x509 details",
}

api_id = None
api_secret = None


def handler(q=False):
    global api_id, api_secret
    if q is False:
        return False
    request = json.loads(q)

    if request.get("config"):
        if (request["config"].get("api_id") is None) or (request["config"].get("api_secret") is None):
            misperrors["error"] = "Censys API credentials are missing"
            return misperrors
    else:
        misperrors["error"] = "Please provide config options"
        return misperrors

    api_id = request["config"]["api_id"]
    api_secret = request["config"]["api_secret"]

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if not any(input_type == attribute["type"] for input_type in mispattributes["input"]):
        return {"error": "Unsupported attribute type."}

    attribute = MISPAttribute()
    attribute.from_dict(**request["attribute"])
    # Lists to accomodate multi-types attribute
    types = list()
    values = list()
    results = list()

    if "|" in attribute.type:
        t_1, t_2 = attribute.type.split("|")
        v_1, v_2 = attribute.value.split("|")
        # We cannot use the port information
        if t_2 == "port":
            types.append(t_1)
            values.append(v_1)
        else:
            types = [t_1, t_2]
            values = [v_1, v_2]
    else:
        types.append(attribute.type)
        values.append(attribute.value)

    found = False
    for t in types:
        try:
            value = values.pop(0)
            # ip, ip-src or ip-dst
            if t[:2] == "ip":
                r = CensysHosts(api_id, api_secret).view(value)
                results.append(parse_response(r, attribute))
                found = True
            elif t == "domain" or t == "hostname":
                # get ips
                endpoint = CensysHosts(api_id, api_secret)
                for r_list in endpoint.search(query=value, per_page=5, pages=1):
                    for r in r_list:
                        results.append(parse_response(r, attribute))
                        found = True
            elif "x509-fingerprint-sha256" in t:
                # use api_v1 as Certificates endpoint in api_v2 doesn't yet provide all the details
                r = CensysCertificates(api_id, api_secret).view(value)
                results.append(parse_response(r, attribute))
                found = True
        except CensysException as e:
            misperrors["error"] = "ERROR: param {} / response: {}".format(value, e)
            return misperrors

    if not found:
        misperrors["error"] = "Nothing could be found on Censys"
        return misperrors

    return {"results": remove_duplicates(results)}


def parse_response(censys_output, attribute):
    misp_event = MISPEvent()
    misp_event.add_attribute(**attribute)
    # Generic fields (for IP/Websites)
    if censys_output.get("autonomous_system"):
        cen_as = censys_output.get("autonomous_system")
        asn_object = MISPObject("asn")
        asn_object.add_attribute("asn", value=cen_as.get("asn"))
        asn_object.add_attribute("description", value=cen_as.get("name"))
        asn_object.add_attribute("subnet-announced", value=cen_as.get("routed_prefix"))
        asn_object.add_attribute("country", value=cen_as.get("country_code"))
        asn_object.add_reference(attribute.uuid, "associated-to")
        misp_event.add_object(**asn_object)

    if censys_output.get("ip") and len(censys_output.get("services")):  # "ports" in censys_output
        ip_object = MISPObject("ip-port")
        ip_object.add_attribute("ip", value=censys_output.get("ip"))
        for serv in censys_output.get("services"):
            if serv.get("port"):
                ip_object.add_attribute("dst-port", value=serv.get("port"))
        ip_object.add_reference(attribute.uuid, "associated-to")
        misp_event.add_object(**ip_object)

    # We explore all ports to find https or ssh services
    for serv in censys_output.get("services", []):
        if not isinstance(serv, dict):
            continue
        if serv.get("service_name").lower() == "http" and serv.get("certificate", None):
            try:
                cert = serv.get("certificate", None)
                if cert:
                    # TODO switch to api_v2 once available
                    # use api_v1 as Certificates endpoint in api_v2 doesn't yet provide all the details
                    cert_details = CensysCertificates(api_id, api_secret).view(cert)
                    cert_obj = get_certificate_object(cert_details, attribute)
                    misp_event.add_object(**cert_obj)
            except KeyError:
                print("Error !")
        if serv.get("ssh") and serv.get("service_name").lower() == "ssh":
            try:
                cert = serv.get("ssh").get("server_host_key").get("fingerprint_sha256")
                # TODO enable once the type is merged
                # misp_event.add_attribute(type='hasshserver-sha256', value=cert['fingerprint_sha256'])
            except KeyError:
                pass

    # Info from certificate query
    if "parsed" in censys_output:
        cert_obj = get_certificate_object(censys_output, attribute)
        misp_event.add_object(**cert_obj)

    # Location can be present for IP/Websites results
    if "location" in censys_output:
        loc_obj = MISPObject("geolocation")
        loc = censys_output["location"]
        loc_obj.add_attribute("latitude", value=loc.get("coordinates", {}).get("latitude", None))
        loc_obj.add_attribute("longitude", value=loc.get("coordinates", {}).get("longitude", None))
        if "city" in loc:
            loc_obj.add_attribute("city", value=loc.get("city"))
        loc_obj.add_attribute("country", value=loc.get("country"))
        if "postal_code" in loc:
            loc_obj.add_attribute("zipcode", value=loc.get("postal_code"))
        if "province" in loc:
            loc_obj.add_attribute("region", value=loc.get("province"))
        loc_obj.add_reference(attribute.uuid, "associated-to")
        misp_event.add_object(**loc_obj)

    event = json.loads(misp_event.to_json())
    return {"Object": event.get("Object", []), "Attribute": event.get("Attribute", [])}


# In case of multiple enrichment (ip and domain), we need to filter out similar objects
# TODO: make it more granular
def remove_duplicates(results):
    # Only one enrichment was performed so no duplicate
    if len(results) == 1:
        return results[0]
    else:
        final_result = results[0]
        for i, result in enumerate(results[1:]):
            obj_l = results[i + 1].get("Object", [])
            for o2 in obj_l:
                if o2["name"] == "asn":
                    key = "asn"
                elif o2["name"] == "ip-port":
                    key = "ip"
                elif o2["name"] == "x509":
                    key = "x509-fingerprint-sha256"
                elif o2["name"] == "geolocation":
                    key = "latitude"
                if not check_if_present(o2, key, final_result.get("Object", [])):
                    final_result["Object"].append(o2)

    return final_result


def check_if_present(object, attribute_name, list_objects):
    """
    Assert if a given object is present in the list.

    This function check if object (json format) is present in list_objects
    using attribute_name for the matching
    """
    for o in list_objects:
        # We first look for a match on the name
        if o["name"] == object["name"]:
            for attr in object["Attribute"]:
                # Within the attributes, we look for the one to compare
                if attr["type"] == attribute_name:
                    # Then we check the attributes of the other object and look for a match
                    for attr2 in o["Attribute"]:
                        if attr2["type"] == attribute_name and attr2["value"] == attr["value"]:
                            return True

    return False


def get_certificate_object(cert, attribute):
    parsed = cert["parsed"]
    cert_object = MISPObject("x509")
    cert_object.add_attribute("x509-fingerprint-sha256", value=parsed["fingerprint_sha256"])
    cert_object.add_attribute("x509-fingerprint-sha1", value=parsed["fingerprint_sha1"])
    cert_object.add_attribute("x509-fingerprint-md5", value=parsed["fingerprint_md5"])
    cert_object.add_attribute("serial-number", value=parsed["serial_number"])
    cert_object.add_attribute("version", value=parsed["version"])
    cert_object.add_attribute("subject", value=parsed["subject_dn"])
    cert_object.add_attribute("issuer", value=parsed["issuer_dn"])
    cert_object.add_attribute("validity-not-before", value=isoparse(parsed["validity"]["start"]))
    cert_object.add_attribute("validity-not-after", value=isoparse(parsed["validity"]["end"]))
    cert_object.add_attribute("self_signed", value=parsed["signature"]["self_signed"])
    cert_object.add_attribute("signature_algorithm", value=parsed["signature"]["signature_algorithm"]["name"])

    cert_object.add_attribute(
        "pubkey-info-algorithm",
        value=parsed["subject_key_info"]["key_algorithm"]["name"],
    )

    if "rsa_public_key" in parsed["subject_key_info"]:
        pub_key = parsed["subject_key_info"]["rsa_public_key"]
        cert_object.add_attribute("pubkey-info-size", value=pub_key["length"])
        cert_object.add_attribute("pubkey-info-exponent", value=pub_key["exponent"])
        hex_mod = codecs.encode(base64.b64decode(pub_key["modulus"]), "hex").decode()
        cert_object.add_attribute("pubkey-info-modulus", value=hex_mod)

    if "extensions" in parsed and "subject_alt_name" in parsed["extensions"]:
        san = parsed["extensions"]["subject_alt_name"]
        if "dns_names" in san:
            for dns in san["dns_names"]:
                cert_object.add_attribute("dns_names", value=dns)
        if "ip_addresses" in san:
            for ip in san["ip_addresses"]:
                cert_object.add_attribute("ip", value=ip)

    if "raw" in cert:
        cert_object.add_attribute("raw-base64", value=cert["raw"])

    cert_object.add_reference(attribute.uuid, "associated-to")
    return cert_object


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
