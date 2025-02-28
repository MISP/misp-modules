#!/usr/bin/env python3

"""
Import VulnDB
    https://vulndb.cyberriskanalytics.com/
    https://www.riskbasedsecurity.com/
"""

import json
import logging
import sys

import oauth2 as oauth

log = logging.getLogger("vulndb")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)


misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "output": ["text", "link", "cpe"]}
moduleinfo = {
    "version": "0.1",
    "author": "Koen Van Impe",
    "description": "Module to query VulnDB (RiskBasedSecurity.com).",
    "module-type": ["expansion", "hover"],
    "name": "VulnDB Lookup",
    "logo": "vulndb.png",
    "requirements": ["An access to the VulnDB API (apikey, apisecret)"],
    "features": (
        "This module takes a vulnerability attribute as input and queries VulnDB in order to get some additional data"
        " about it.\n\nThe API gives the result of the query which can be displayed in the screen, and/or mapped into"
        " MISP attributes to add in the event."
    ),
    "references": ["https://vulndb.cyberriskanalytics.com/"],
    "input": "A vulnerability attribute.",
    "output": "Additional data enriching the CVE input, fetched from VulnDB.",
}

moduleconfig = [
    "apikey",
    "apisecret",
    "discard_dates",
    "discard_external_references",
    "discard_cvss",
    "discard_productinformation",
    "discard_classification",
    "discard_cpe",
]


def handler(q=False):
    # Base URL for VulnDB
    VULNDB_URL = "https://vulndb.cyberriskanalytics.com"

    if q is False:
        return False
    request = json.loads(q)

    # Only continue if we have a vulnerability attribute
    if not request.get("vulnerability"):
        misperrors["error"] = "Vulnerability ID missing for VulnDB."
        return misperrors
    vulnerability = request.get("vulnerability")

    if request["config"].get("apikey") is None or request["config"].get("apisecret") is None:
        misperrors["error"] = "Missing API key or secret value for VulnDB."
        return misperrors
    apikey = request["config"].get("apikey")
    apisecret = request["config"].get("apisecret")

    # This has to be done the 'inverse' way, MISP-server settings are set to False by default
    add_cvss = True
    add_products = True
    add_classifications = True
    add_cpe = True
    add_dates = True
    add_ext_references = True

    if request["config"].get("discard_dates") is not None and request["config"].get("discard_dates").lower() == "true":
        add_dates = False
    if (
        request["config"].get("discard_external_references") is not None
        and request["config"].get("discard_external_references").lower() == "true"
    ):
        add_ext_references = False
    if request["config"].get("discard_cvss") is not None and request["config"].get("discard_cvss").lower() == "true":
        add_cvss = False
    if (
        request["config"].get("discard_productinformation") is not None
        and request["config"].get("discard_productinformation").lower() == "true"
    ):
        add_products = False
    if (
        request["config"].get("discard_classification") is not None
        and request["config"].get("discard_classification").lower() == "true"
    ):
        add_classifications = False
    if request["config"].get("discard_cpe") is not None and request["config"].get("discard_cpe").lower() == "true":
        add_cpe = False

    cpu_vulndb = ""
    if add_cpe:
        cpu_vulndb = "?show_cpe=true"

    find_by_cve_url = "%s/api/v1/vulnerabilities/%s/find_by_cve_id%s" % (
        VULNDB_URL,
        vulnerability,
        cpu_vulndb,
    )
    log.debug(find_by_cve_url)

    try:

        consumer = oauth.Consumer(key=apikey, secret=apisecret)
        client = oauth.Client(consumer)
        resp, content = client.request(find_by_cve_url, "GET")
        content_json = json.loads(content.decode())

        if content_json:
            if "error" in content_json:
                misperrors["error"] = "No CVE information found."
                return misperrors
            else:
                output = {"results": list()}
                values_text = list()
                values_links = list()
                values_cpe = list()

                results = content_json["results"][0]

                # Include the VulnDB title and ID
                values_text.append(results["title"])
                vulndb_id_link = "%s/vulnerabilities/%s" % (
                    VULNDB_URL,
                    results["vulndb_id"],
                )
                values_links.append(vulndb_id_link)

                # Descriptive part of the VulnDB item
                description = results.get("description", "") or ""
                keywords = results.get("keywords", "") or ""
                solution = results.get("solution", "") or ""
                manual_notes = results.get("manual_notes", "") or ""
                t_description = results.get("t_description", "") or ""
                if description:
                    values_text.append(description)
                if t_description:
                    values_text.append(t_description)
                if manual_notes:
                    values_text.append("Notes: " + manual_notes)
                if keywords:
                    values_text.append("Keywords: " + keywords)
                if solution:
                    values_text.append("Solution: " + solution)

                # VulnDB items contain a number of dates, do we include them?
                if add_dates:
                    log.debug("Include dates")
                    solution_date = results.get("solution_date", "") or ""
                    if solution_date:
                        values_text.append("Solution date: " + solution_date)
                    disclosure_date = results.get("disclosure_date", "") or ""
                    if disclosure_date:
                        values_text.append("Disclosure date: " + disclosure_date)
                    discovery_date = results.get("discovery_date", "") or ""
                    if discovery_date:
                        values_text.append("Discovery date: " + discovery_date)
                    exploit_publish_date = results.get("exploit_publish_date", "") or ""
                    if exploit_publish_date:
                        values_text.append("Exploit published date: " + exploit_publish_date)
                    vendor_informed_date = results.get("vendor_informed_date", "") or ""
                    if vendor_informed_date:
                        values_text.append("Vendor informed date: " + vendor_informed_date)
                    vendor_ack_date = results.get("vendor_ack_date", "") or ""
                    if vendor_ack_date:
                        values_text.append("Vendor acknowledgement date: " + vendor_ack_date)
                    third_party_solution_date = results.get("third_party_solution_date", "") or ""
                    if third_party_solution_date:
                        values_text.append("Third party solution date: " + third_party_solution_date)

                # External references
                if add_ext_references:
                    ext_references = results.get("ext_references")
                    if ext_references:
                        log.debug("Include external references")
                        for reference in ext_references:
                            reference_type = reference["type"]
                            if reference_type == "Other Advisory URL":
                                values_links.append(reference["value"])
                            elif reference_type == "News Article":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Vendor Specific Advisory URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Vendor URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Mail List Post":
                                values_links.append(reference["value"])
                            elif reference_type == "Metasploit URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Packet Storm":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Exploit URL":
                                values_links.append(reference["value"])
                            elif reference_type == "CERT VU":
                                reference_link = "http://www.kb.cert.org/vuls/id/%s" % reference["value"]
                                values_links.append(reference_link)
                            elif reference_type == "CVE ID":
                                reference_link = "https://nvd.nist.gov/vuln/detail/%s" % reference["value"]
                                values_links.append(reference_link)
                            elif reference_type == "Microsoft Knowledge Base Article":
                                reference_link = "https://support.microsoft.com/en-us/help/%s" % reference["value"]
                                values_links.append(reference_link)
                            elif reference_type == "Exploit Database":
                                reference_link = "https://www.exploit-db.com/exploits/%s" % reference["value"]
                                values_links.append(reference_link)
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])
                            elif reference_type == "Generic Informational URL":
                                values_links.append(reference["value"])

                # CVSS Scoring
                if add_cvss:
                    cvss = results.get("cvss_metrics")
                    if cvss:
                        log.debug("Include CVSS")
                        for cvss_metric in cvss:
                            score = cvss_metric.get("score")
                            if score:
                                values_text.append(
                                    "CVSS %s (base: %s) (source: %s)"
                                    % (
                                        score,
                                        cvss_metric.get("calculated_cvss_base_score"),
                                        cvss_metric.get("source"),
                                    )
                                )

                # Add products
                if add_products:
                    products = results.get("products")
                    if products and len(products) > 0:

                        # Get the vendors
                        vendors = results.get("vendors")
                        vendors_name = ""
                        log.debug("Include product information")
                        if vendors:
                            for vendor in vendors:
                                vendor_detail = vendor.get("vendor")
                                if vendor_detail:
                                    vendor_name = vendor_detail.get("name")
                                    if vendor_name:
                                        vendors_name += vendor_name + " "

                        # Walk through all vendors
                        for product in products:
                            vulnerable_product = vendors_name
                            name = product.get("name")
                            if name:
                                vulnerable_product += "%s " % name
                            versions = product.get("versions")
                            if versions:
                                vulnerable_product += "("
                                for version in versions:
                                    affected = version.get("affected")

                                    if affected and affected == "true":
                                        vulnerable_product += " %s " % version.get("name")
                                    if add_cpe:
                                        version_cpe = version.get("cpe")
                                        if version_cpe:
                                            cpe = version_cpe[0].get("cpe")
                                            if cpe:
                                                values_cpe.append(cpe)

                                vulnerable_product += ")"
                            # Add vulnerable products
                            values_text.append(vulnerable_product)

                # Add vulnerability classifications
                if add_classifications:
                    classifications = results.get("classifications")
                    if classifications and len(classifications) > 0:
                        vulnerability_classification = ""
                        log.debug("Include classifications")
                        for classification in classifications:
                            longname = classification.get("longname")
                            description = classification.get("description")
                            vulnerability_classification += ' "%s" ' % longname
                        values_text.append(vulnerability_classification)

                # Finished processing the VulnDB reply; set the result for MISP
                output["results"] += [{"types": "text", "values": values_text}]
                output["results"] += [{"types": "link", "values": values_links}]
                if add_cpe:
                    output["results"] += [{"types": "cpe", "values": values_cpe}]
                return output
        else:
            misperrors["error"] = "No information retrieved from VulnDB."
            return misperrors
    except Exception:
        misperrors["error"] = "Error while fetching information from VulnDB, wrong API keys?"
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
