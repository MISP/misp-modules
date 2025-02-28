import json
from base64 import b64encode
from collections import OrderedDict
from urllib.parse import quote

import pymisp
from pymisp import MISPAttribute, MISPEvent, MISPObject
from trustar import Indicator, TruStar

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "btc",
        "domain",
        "email-src",
        "filename",
        "hostname",
        "ip-src",
        "ip-dst",
        "malware-type",
        "md5",
        "sha1",
        "sha256",
        "url",
    ],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.1",
    "author": "Jesse Hedden",
    "description": "Module to get enrich indicators with TruSTAR.",
    "module-type": ["hover", "expansion"],
    "name": "TruSTAR Enrich",
    "logo": "trustar.png",
    "requirements": [],
    "features": (
        "This module enriches MISP attributes with scoring and metadata from TruSTAR.\n\nThe TruSTAR indicator summary"
        " is appended to the attributes along with links to any associated reports."
    ),
    "references": ["https://docs.trustar.co/api/v13/indicators/get_indicator_summaries.html"],
    "input": (
        "Any of the following MISP attributes:\n- btc\n- domain\n- email-src\n- filename\n- hostname\n- ip-src\n-"
        " ip-dst\n- md5\n- sha1\n- sha256\n- url"
    ),
    "output": (
        "MISP attributes enriched with indicator summary data from the TruSTAR API. Data includes a severity level"
        " score and additional source and scoring info."
    ),
}

moduleconfig = ["user_api_key", "user_api_secret", "enclave_ids"]

MAX_PAGE_SIZE = 100  # Max allowable page size returned from /1.3/indicators/summaries endpoint


class TruSTARParser:
    ENTITY_TYPE_MAPPINGS = {
        "BITCOIN_ADDRESS": "btc",
        "CIDR_BLOCK": "ip-src",
        "CVE": "vulnerability",
        "URL": "url",
        "EMAIL_ADDRESS": "email-src",
        "SOFTWARE": "filename",
        "IP": "ip-src",
        "MALWARE": "malware-type",
        "MD5": "md5",
        "REGISTRY_KEY": "regkey",
        "SHA1": "sha1",
        "SHA256": "sha256",
    }

    # Relevant fields from each TruSTAR endpoint
    SUMMARY_FIELDS = ["severityLevel", "source", "score", "attributes"]
    METADATA_FIELDS = ["sightings", "firstSeen", "lastSeen", "tags"]

    REPORT_BASE_URL = "https://station.trustar.co/constellation/reports/{}"

    CLIENT_METATAG = f"MISP-{pymisp.__version__}"

    def __init__(self, attribute, config):
        config["enclave_ids"] = config.get("enclave_ids", "").strip().split(",")
        config["client_metatag"] = self.CLIENT_METATAG
        self.ts_client = TruStar(config=config)

        self.misp_event = MISPEvent()
        self.misp_attribute = MISPAttribute()
        self.misp_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.misp_attribute)

    def get_results(self):
        """
        Returns the MISP Event enriched with TruSTAR indicator summary data.
        """
        try:
            event = json.loads(self.misp_event.to_json())
            results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
            return {"results": results}
        except Exception as e:
            misperrors["error"] += f" -- Encountered issue serializing enrichment data -- {e}"
            return misperrors

    def generate_trustar_link(self, entity_type, entity_value):
        """
        Generates link to TruSTAR report of entity.

        :param entity_type: <str> Type of entity.
        :param entity_value: <str> Value of entity.
        :return: <str> Link to indicator report in TruSTAR platform.
        """
        report_id = b64encode(quote(f"{entity_type}|{entity_value}").encode()).decode()

        return self.REPORT_BASE_URL.format(report_id)

    @staticmethod
    def extract_tags(enrichment_report):
        """
        Extracts tags from the enrichment report in order to add them
        to the TruSTAR MISP Object. Removes tags from report to avoid
        redundancy.

        :param: <OrderedDict> Enrichment data.
        :return: <list> List of tags.
        """
        if enrichment_report and enrichment_report.get("tags"):
            return [tag.get("name") for tag in enrichment_report.pop("tags")]
        return None

    def generate_enrichment_report(self, summary, metadata):
        """
        Extracts desired fields from summary and metadata reports and
        generates an enrichment report.

        :param summary: <trustar.IndicatorSummary> Indicator summary report.
        :param metadata: <trustar.Indicator> Indicator metadata report.
        :return: <str> Enrichment report.
        """
        # Preserve order of fields as they exist in SUMMARY_FIELDS and METADATA_FIELDS
        enrichment_report = OrderedDict()

        if summary:
            summary_dict = summary.to_dict()
            enrichment_report.update(
                {field: summary_dict[field] for field in self.SUMMARY_FIELDS if summary_dict.get(field)}
            )

        if metadata:
            metadata_dict = metadata.to_dict()
            enrichment_report.update(
                {field: metadata_dict[field] for field in self.METADATA_FIELDS if metadata_dict.get(field)}
            )

        return enrichment_report

    def parse_indicator_summary(self, indicator, summary, metadata):
        """
        Pulls enrichment data from the TruSTAR /indicators/summaries and /indicators/metadata endpoints
        and creates a MISP trustar_report.

        :param indicator: <str> Value of the attribute
        :summary: <trustar.IndicatorSummary> Indicator summary response object.
        :metadata: <trustar.Indicator> Indicator response object.
        """

        # Verify that the indicator type is supported by TruSTAR
        if summary and summary.indicator_type in self.ENTITY_TYPE_MAPPINGS:
            indicator_type = summary.indicator_type
        elif metadata and metadata.type in self.ENTITY_TYPE_MAPPINGS:
            indicator_type = metadata.type
        else:
            misperrors["error"] += " -- Attribute not found or not supported"
            raise Exception

        try:
            # Extract most relevant fields from indicator summary and metadata responses
            enrichment_report = self.generate_enrichment_report(summary, metadata)
            tags = self.extract_tags(enrichment_report)

            if enrichment_report:
                # Create MISP trustar_report object and populate it with enrichment data
                trustar_obj = MISPObject("trustar_report")
                trustar_obj.add_attribute(
                    indicator_type,
                    attribute_type=self.ENTITY_TYPE_MAPPINGS[indicator_type],
                    value=indicator,
                )
                trustar_obj.add_attribute(
                    "INDICATOR_SUMMARY",
                    attribute_type="text",
                    value=json.dumps(enrichment_report, indent=4),
                )

                report_link = self.generate_trustar_link(indicator_type, indicator)
                trustar_obj.add_attribute("REPORT_LINK", attribute_type="link", value=report_link)

                self.misp_event.add_object(**trustar_obj)
            elif not tags:
                # If enrichment report is empty and there are no tags, nothing to add to attribute
                raise Exception("No relevant data found")

            if tags:
                for tag in tags:
                    self.misp_event.add_attribute_tag(tag, indicator)

        except Exception as e:
            misperrors["error"] += f" -- Error enriching attribute {indicator} -- {e}"
            raise e


def handler(q=False):
    """
    MISP handler function. A user's API key and secret will be retrieved from the MISP
    request and used to create a TruSTAR API client. If enclave IDs are provided, only
    those enclaves will be queried for data. Otherwise, all of the enclaves a user has
    access to will be queried.
    """

    if q is False:
        return False

    request = json.loads(q)

    config = request.get("config", {})
    if not config.get("user_api_key") or not config.get("user_api_secret"):
        misperrors["error"] = "Your TruSTAR API key and secret are required for indicator enrichment."
        return misperrors

    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error}."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    trustar_parser = TruSTARParser(attribute, config)
    metadata = None
    summary = None

    try:
        metadata = trustar_parser.ts_client.get_indicators_metadata([Indicator(value=attribute["value"])])[0]
    except IndexError:
        misperrors["error"] += f" -- No metadata found for indicator {attribute['value']}"
    except Exception as e:
        misperrors["error"] += f" -- Could not retrieve indicator metadata from TruSTAR {e}"

    try:
        summary = list(trustar_parser.ts_client.get_indicator_summaries([attribute["value"]], page_size=MAX_PAGE_SIZE))[
            0
        ]
    except IndexError:
        misperrors["error"] += f" -- No summary data found for indicator {attribute['value']}"
    except Exception as e:
        misperrors["error"] += f" -- Unable to retrieve TruSTAR summary data: {e}"

    try:
        trustar_parser.parse_indicator_summary(attribute["value"], summary, metadata)
    except Exception:
        return misperrors

    return trustar_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
