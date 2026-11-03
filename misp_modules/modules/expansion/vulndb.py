#!/usr/bin/env python3

"""
Import VulnDB
    https://vulndb.flashpoint.io/
"""

import json
import logging
from urllib.parse import quote

import requests

log = logging.getLogger("vulndb")
VULNDB_URL = "https://vulndb.flashpoint.io"
REQUEST_TIMEOUT = 30

mispattributes = {"input": ["vulnerability"], "output": ["text", "link", "cpe"]}
moduleinfo = {
    "version": "0.2",
    "author": "Koen Van Impe",
    "description": "Module to query VulnDB (Flashpoint).",
    "module-type": ["expansion", "hover"],
    "name": "VulnDB Lookup",
    "logo": "vulndb.png",
    "requirements": ["VulnDB OAuth 2.0 client credentials (apikey: client ID, apisecret: client secret)"],
    "features": (
        "This module takes a vulnerability attribute as input and queries VulnDB in order to get some additional data"
        " about it.\n\nThe API gives the result of the query which can be displayed in the screen, and/or mapped into"
        " MISP attributes to add in the event.\n\nRegister an OAuth client application in VulnDB under API > Overview."
        " Set apikey to its client ID and apisecret to its client secret. Legacy OAuth 1 consumer credentials must be"
        " replaced with OAuth 2.0 client credentials. Authentication uses requests; the legacy oauth2 package is no"
        " longer required."
    ),
    "references": ["https://vulndb.flashpoint.io/"],
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


def _check_response(response):
    response.raise_for_status()
    # Do not follow redirects to an interactive sign-in page or another host.
    if not 200 <= response.status_code < 300:
        raise requests.HTTPError(response=response)
    return response.json()


def _query_vulndb(vulnerability, apikey, apisecret, add_cpe):
    with requests.Session() as session:
        token_data = _check_response(
            session.post(
                f"{VULNDB_URL}/oauth/token",
                json={"grant_type": "client_credentials", "client_id": apikey, "client_secret": apisecret},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        )
        token = token_data.get("access_token") if isinstance(token_data, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise ValueError("Missing VulnDB access token")
        return _check_response(
            session.get(
                f"{VULNDB_URL}/api/v1/vulnerabilities/{quote(vulnerability, safe='')}/find_by_cve_id",
                params={"show_cpe": "true"} if add_cpe else {},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        )


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "Invalid JSON request for VulnDB."}
    if not isinstance(request, dict):
        return {"error": "Invalid request for VulnDB."}

    vulnerability = request.get("vulnerability")
    if not isinstance(vulnerability, str) or not vulnerability.strip():
        return {"error": "Vulnerability ID missing for VulnDB."}
    vulnerability = vulnerability.strip()

    config = request.get("config") or {}
    if not isinstance(config, dict) or not all(
        isinstance(config.get(key), str) and config[key].strip() for key in ("apikey", "apisecret")
    ):
        return {"error": "Missing OAuth 2.0 client ID (apikey) or client secret (apisecret) for VulnDB."}

    # MISP settings default to False, so information is included unless discarded.
    add_dates = str(config.get("discard_dates", False)).lower() != "true"
    add_ext_references = str(config.get("discard_external_references", False)).lower() != "true"
    add_cvss = str(config.get("discard_cvss", False)).lower() != "true"
    add_products = str(config.get("discard_productinformation", False)).lower() != "true"
    add_classifications = str(config.get("discard_classification", False)).lower() != "true"
    add_cpe = str(config.get("discard_cpe", False)).lower() != "true"

    try:
        content_json = _query_vulndb(vulnerability, config["apikey"], config["apisecret"], add_cpe)
        if not isinstance(content_json, dict):
            return {"error": "Invalid response from VulnDB."}
        if "error" in content_json or not content_json.get("results"):
            return {"error": "No CVE information found."}
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

    except requests.Timeout:
        return {"error": "VulnDB request timed out."}
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status in (400, 401, 403):
            return {
                "error": (
                    "VulnDB authentication or access denied. Check your OAuth 2.0 client credentials and API"
                    " permissions."
                )
            }
        if status == 404:
            return {"error": "No CVE information found."}
        if status == 429:
            return {"error": "VulnDB API rate limit exceeded. Try again later."}
        return {"error": "VulnDB API returned an unexpected HTTP response."}
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        return {"error": "Invalid response from VulnDB."}
    except requests.RequestException:
        return {"error": "Unable to connect to the VulnDB API."}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
