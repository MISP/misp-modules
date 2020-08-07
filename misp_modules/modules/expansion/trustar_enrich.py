import json
import pymisp
from base64 import b64encode
from collections import OrderedDict
from pymisp import MISPAttribute, MISPEvent, MISPObject
from trustar import TruStar
from urllib.parse import quote

misperrors = {'error': "Error"}
mispattributes = {
    'input': ["btc", "domain", "email-src", "filename", "hostname", "ip-src", "ip-dst", "malware-type", "md5", "sha1",
              "sha256", "url"], 'format': 'misp_standard'}

moduleinfo = {'version': "0.1", 'author': "Jesse Hedden",
              'description': "Enrich data with TruSTAR",
              'module-type': ["hover", "expansion"]}

moduleconfig = ["user_api_key", "user_api_secret", "enclave_ids"]

MAX_PAGE_SIZE = 100  # Max allowable page size returned from /1.3/indicators/summaries endpoint


class TruSTARParser:
    ENTITY_TYPE_MAPPINGS = {
        'BITCOIN_ADDRESS': "btc",
        'CIDR_BLOCK': "ip-src",
        'CVE': "vulnerability",
        'URL': "url",
        'EMAIL_ADDRESS': "email-src",
        'SOFTWARE': "filename",
        'IP': "ip-src",
        'MALWARE': "malware-type",
        'MD5': "md5",
        'REGISTRY_KEY': "regkey",
        'SHA1': "sha1",
        'SHA256': "sha256"
    }

    SUMMARY_FIELDS = ["source", "score", "attributes"]
    METADATA_FIELDS = ["sightings", "first_seen", "last_seen", "tags"]

    REPORT_BASE_URL = "https://station.trustar.co/constellation/reports/{}"

    CLIENT_METATAG = f"MISP-{pymisp.__version__}"

    def __init__(self, attribute, config):
        config['enclave_ids'] = config.get('enclave_ids', "").strip().split(',')
        config['client_metatag'] = self.CLIENT_METATAG
        self.ts_client = TruStar(config=config)

        self.misp_event = MISPEvent()
        self.misp_attribute = MISPAttribute()
        self.misp_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.misp_attribute)

    def get_results(self):
        """
        Returns the MISP Event enriched with TruSTAR indicator summary data.
        """
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def generate_trustar_link(self, entity_type, entity_value):
        """
        Generates link to TruSTAR report of entity.

        :param entity_value: <str> Value of entity.
        """
        report_id = b64encode(quote(f"{entity_type}|{entity_value}").encode()).decode()

        return self.REPORT_BASE_URL.format(report_id)

    def generate_enrichment_report(self, summary, metadata):
        """
        Extracts desired fields from summary and metadata reports and
        generates an enrichment report.

        :param summary: <dict> Indicator summary report.
        :param metadata: <dict> Indicator metadata report.
        :return: <str> Enrichment report.
        """
        enrichment_report = OrderedDict()

        for field in self.SUMMARY_FIELDS:
            enrichment_report[field] = summary.get(field)

        for field in self.METADATA_FIELDS:
            enrichment_report[field] = metadata.get(field)

        return enrichment_report

    def parse_indicator_summary(self, summaries, metadata):
        """
        Converts a response from the TruSTAR /1.3/indicators/summaries endpoint
        a MISP trustar_report object and adds the summary data and links as attributes.

        :param summaries: <generator> A TruSTAR Python SDK Page.generator object for generating
                          indicator summaries pages.
        """

        for summary in summaries:
            if summary.indicator_type in self.ENTITY_TYPE_MAPPINGS:
                indicator_type = summary.indicator_type
                indicator_value = summary.indicator_value
                try:
                    enrichment_report = self.generate_enrichment_report(summary.to_dict(), metadata.to_dict())
                    trustar_obj = MISPObject('trustar_report')
                    trustar_obj.add_attribute(indicator_type, attribute_type=self.ENTITY_TYPE_MAPPINGS[indicator_type],
                                              value=indicator_value)
                    trustar_obj.add_attribute("INDICATOR_SUMMARY", attribute_type="text",
                                              value=json.dumps(enrichment_report, indent=4))
                    report_link = self.generate_trustar_link(indicator_type, indicator_value)
                    trustar_obj.add_attribute("REPORT_LINK", attribute_type="link", value=report_link)
                    self.misp_event.add_object(**trustar_obj)
                except Exception as e:
                    misperrors['error'] = f"Error enriching data with TruSTAR -- {e}"


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

    config = request.get('config', {})
    if not config.get('user_api_key') or not config.get('user_api_secret'):
        misperrors['error'] = "Your TruSTAR API key and secret are required for indicator enrichment."
        return misperrors

    attribute = request['attribute']
    trustar_parser = TruSTARParser(attribute, config)

    try:
        metadata = trustar_parser.ts_client.get_indicators_metadata([attribute['value']])
        summaries = list(
            trustar_parser.ts_client.get_indicator_summaries([attribute['value']], page_size=MAX_PAGE_SIZE))
    except Exception as e:
        misperrors['error'] = f"Unable to retrieve TruSTAR summary data: {e}"
        return misperrors

    trustar_parser.parse_indicator_summary(summaries)
    return trustar_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
