import json
import pymisp
from pymisp import MISPAttribute, MISPEvent, MISPObject
from trustar import TruStar

misperrors = {'error': "Error"}
mispattributes = {
    'input': ["btc", "domain", "email-src", "filename", "hostname", "ip-src", "ip-dst", "malware-type", "md5", "sha1",
              "sha256", "url"], 'format': 'misp_standard'}

moduleinfo = {'version': "0.1", 'author': "Jesse Hedden",
              'description': "Enrich data with TruSTAR",
              'module-type': ["hover", "expansion"]}

moduleconfig = ["user_api_key", "user_api_secret", "enclave_ids"]


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

    REPORT_BASE_URL = "https://station.trustar.co/constellation/reports/{}"

    CLIENT_METATAG = "TruSTAR-MISP-{}".format(pymisp.__version__)

    def __init__(self, attribute, config):
        config['enclave_ids'] = config.get('enclave_ids', "").split(',')
        config['client_metatag'] = self.CLIENT_METATAG
        self.ts_client = TruStar(config=config)

        self.misp_event = MISPEvent()
        self.misp_attribute = MISPAttribute()
        self.misp_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.misp_attribute)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def generate_trustar_links(self, entity_value):
        """
        Generates links to TruSTAR reports if they exist.

        :param entity_value: <str> Value of entity.
        """
        report_links = list()
        trustar_reports = self.ts_client.search_reports(entity_value)
        for report in trustar_reports:
            report_links.append(self.REPORT_BASE_URL.format(report.id))

        return report_links

    def parse_indicator_summary(self, attribute, summaries):

        for summary in summaries:
            trustar_obj = MISPObject('trustar_report')
            summary_dict = summary.to_dict()
            summary_type = summary_dict.get('type')
            summary_value = summary_dict.get('value')
            if summary_type in self.ENTITY_TYPE_MAPPINGS:
                trustar_obj.add_attribute(summary_type, attribute_type=self.ENTITY_TYPE_MAPPINGS[summary_type],
                                          value=summary_value)
                trustar_obj.add_attribute("INDICATOR_SUMMARY", attribute_type="text",
                                          value=json.dumps(summary_dict, sort_keys=True, indent=4))
                report_links = self.generate_trustar_links(summary_value)
                for link in report_links:
                    trustar_obj.add_attribute("REPORT_LINK", attribute_type="link", value=link)
                self.misp_event.add_object(**trustar_obj)

    def handler(q=False):

        if q is False:
            return False

        request = json.loads(q)

        config = request.get('config', {})
        if not config.get('user_api_key') or not config.get('user_api_secret'):
            misperrors['error'] = "Your TruSTAR API key and secret are required for indicator enrichment."
            return misperrors

        attribute = request['attribute']
        trustar_parser = TruSTARParser(attribute, config)
        summaries = trustar_parser.ts_client.get_indicator_summaries([attribute['value']])
        trustar_parser.parse_indicator_summary(attribute, summaries)
        return trustar_parser.get_results()

    def introspection():
        return mispattributes

    def version():
        moduleinfo['config'] = moduleconfig
        return moduleinfo
