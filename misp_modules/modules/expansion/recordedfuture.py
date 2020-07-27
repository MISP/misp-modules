import json
import logging
import requests
from urllib.parse import quote
from pymisp import MISPAttribute, MISPEvent, MISPTag, MISPObject

moduleinfo = {'version': '1.0', 'author': 'Recorded Future',
              'description': 'Module to retrieve data from Recorded Future',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['token']

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip', 'ip-src', 'ip-dst', 'domain', 'hostname', 'md5', 'sha1', 'sha256',
                            'uri', 'url', 'vulnerability', 'weakness'],
                  'output': ['ip', 'ip-src', 'ip-dst', 'domain', 'hostname', 'md5', 'sha1', 'sha256',
                             'uri', 'url', 'vulnerability', 'weakness', 'email-src', 'text'],
                  'format': 'misp_standard'}

LOGGER = logging.getLogger('recorded_future')
LOGGER.setLevel(logging.INFO)


def rf_lookup(api_token: str, category: str, ioc: str) -> requests.Response:
    """Do a lookup call using Recorded Future's ConnectAPI."""
    auth_header = {"X-RFToken": api_token}
    parsed_ioc = quote(ioc, safe='')
    url = f'https://api.recordedfuture.com/v2/{category}/{parsed_ioc}?fields=risk%2CrelatedEntities'
    response = requests.get(url, headers=auth_header)
    response.raise_for_status()
    return response


class GalaxyFinder:
    """A class for finding MISP galaxy matches to Recorded Future data."""
    def __init__(self):
        self.session = requests.Session()
        self.sources = {
            'RelatedThreatActor': ['https://raw.githubusercontent.com/MISP/misp-galaxy/'
                                   'main/clusters/threat-actor.json'],
            'RelatedMalware': ['https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/banker.json',
                               'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/botnet.json',
                               'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/exploit-kit.json',
                               'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/rat.json',
                               'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json',
                               'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json']
        }
        self.galaxy_clusters = {}

    def pull_galaxy_cluster(self, related_type: str):
        """Fetches galaxy clusters for the related_type from the remote json files specified as self.sources."""
        # Only fetch clusters if not fetched previously
        if not self.galaxy_clusters.get(related_type):
            for source in self.sources.get(related_type):
                response = self.session.get(source)
                if response.ok:
                    name = source.split('/')[-1].split('.')[0]
                    self.galaxy_clusters[related_type] = {name: response.json()}
                else:
                    LOGGER.info(f'pull_galaxy_cluster failed for source: {source},'
                                f' got response: {response}, {response.reason}.')

    def find_galaxy_match(self, indicator: str, related_type: str) -> str:
        """Searches the clusters of the related_type for a match with the indicator.
           :returns the first matching galaxy string or an empty string if no galaxy match is found.
        """
        self.pull_galaxy_cluster(related_type)
        try:
            for cluster_name, cluster in self.galaxy_clusters[related_type].items():
                for value in cluster['values']:
                    try:
                        if indicator in value['meta']['synonyms'] or indicator in value['value']:
                            value = value['value']
                            return f'misp-galaxy:{cluster_name}="{value}"'
                    except KeyError:
                        pass
        except KeyError:
            pass
        return ''


class RFColors:
    """Class for setting signature RF-colors."""
    def __init__(self):
        self.rf_white = '#CCCCCC'
        self.rf_yellow = '#FFCE00'
        self.rf_red = '#CF0A2C'

    def riskscore_color(self, risk_score: int) -> str:
        """Returns appropriate hex-colors according to risk score."""
        risk_score = int(risk_score)
        if risk_score < 25:
            return self.rf_white
        elif risk_score < 65:
            return self.rf_yellow
        else:
            return self.rf_red

    def riskrule_color(self, risk_rule_criticality: int) -> str:
        """Returns appropriate hex-colors according to risk rule criticality."""
        risk_rule_criticality = int(risk_rule_criticality)
        if risk_rule_criticality == 1:
            return self.rf_white
        elif risk_rule_criticality == 2:
            return self.rf_yellow
        else:  # risk_rule_criticality == 3 or 4
            return self.rf_red


class RFEnricher:
    """Class for enriching an attribute with data from Recorded Future.
       The enrichment data is returned as a custom MISP object.
    """
    def __init__(self, api_token: str, attribute_props: dict):
        self.api_token = api_token
        self.event = MISPEvent()
        self.enrichment_object = MISPObject('Recorded Future Enrichment')
        self.enrichment_object.from_dict(**{'meta-category': 'misc',
                                            'description': 'An object containing the enriched attribute and related '
                                                           'entities from Recorded Future.',
                                            'distribution': 0})

        # Create a copy of enriched attribute to add tags to
        temp_attr = MISPAttribute()
        temp_attr.from_dict(**attribute_props)
        self.enriched_attribute = MISPAttribute()
        self.enriched_attribute.from_dict(**{'value': temp_attr.value, 'type': temp_attr.type, 'distribution': 0})

        self.related_attributes = []
        self.color_picker = RFColors()
        self.galaxy_finder = GalaxyFinder()

        # Mapping from MISP-type to RF-type
        self.type_to_rf_category = {'ip': 'ip', 'ip-src': 'ip', 'ip-dst': 'ip',
                                    'domain': 'domain', 'hostname': 'domain',
                                    'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash',
                                    'uri': 'url', 'url': 'url',
                                    'vulnerability': 'vulnerability', 'weakness': 'vulnerability'}

        # Related entities from RF portrayed as related attributes in MISP
        self.related_attribute_types = ['RelatedIpAddress', 'RelatedInternetDomainName', 'RelatedHash',
                                        'RelatedEmailAddress', 'RelatedCyberVulnerability']
        # Related entities from RF portrayed as tags in MISP
        self.galaxy_tag_types = ['RelatedMalware', 'RelatedThreatActor']

    def enrich(self):
        """Run the enrichment."""
        category = self.type_to_rf_category.get(self.enriched_attribute.type)

        try:
            response = rf_lookup(self.api_token, category, self.enriched_attribute.value)
            json_response = json.loads(response.content)
        except requests.HTTPError as error:
            misperrors['error'] = f'Error when requesting data from Recorded Future. ' \
                                  f'{error.response} : {error.response.reason}'
            raise error

        try:
            # Add risk score and risk rules as tags to the enriched attribute
            risk_score = json_response['data']['risk']['score']
            hex_color = self.color_picker.riskscore_color(risk_score)
            tag_name = f'recorded-future:risk-score="{risk_score}"'
            self.add_tag(tag_name, hex_color)
            for evidence in json_response['data']['risk']['evidenceDetails']:
                risk_rule = evidence['rule']
                criticality = evidence['criticality']
                hex_color = self.color_picker.riskrule_color(criticality)
                tag_name = f'recorded-future:risk-rule="{risk_rule}"'
                self.add_tag(tag_name, hex_color)

            # Retrieve related entities
            for related_entity in json_response['data']['relatedEntities']:
                related_type = related_entity['type']
                if related_type in self.related_attribute_types:
                    # Related entities returned as additional attributes
                    for related in related_entity['entities']:
                        if int(related["count"]) > 4:
                            indicator = related['entity']['name']
                            self.add_related_attribute(indicator, related_type)
                elif related_type in self.galaxy_tag_types:
                    # Related entities added as galaxy-tags to the enriched attribute
                    galaxy_tags = []
                    for related in related_entity['entities']:
                        if int(related["count"]) > 4:
                            indicator = related['entity']['name']
                            galaxy = self.galaxy_finder.find_galaxy_match(indicator, related_type)
                            # Handle deduplication of galaxy tags
                            if galaxy and galaxy not in galaxy_tags:
                                galaxy_tags.append(galaxy)
                    for galaxy in galaxy_tags:
                        self.add_tag(galaxy)
        except KeyError as error:
            misperrors['error'] = 'Unexpected format in Recorded Future api response.'
            raise error

    def add_related_attribute(self, indicator: str, related_type: str) -> None:
        """Helper method for adding an indicator to the related attribute list."""
        out_type = self.get_output_type(related_type, indicator)
        attribute = MISPAttribute()
        attribute.from_dict(**{'value': indicator, 'type': out_type, 'distribution': 0})
        self.related_attributes.append((related_type, attribute))

    def add_tag(self, tag_name: str, hex_color: str = None) -> None:
        """Helper method for adding a tag to the enriched attribute."""
        tag = MISPTag()
        tag_properties = {'name': tag_name}
        if hex_color:
            tag_properties['colour'] = hex_color
        tag.from_dict(**tag_properties)
        self.enriched_attribute.add_tag(tag)

    def get_output_type(self, related_type: str, indicator: str) -> str:
        """Helper method for translating a Recorded Future related type to a MISP output type."""
        output_type = 'text'
        if related_type == 'RelatedIpAddress':
            output_type = 'ip-dst'
        elif related_type == 'RelatedInternetDomainName':
            output_type = 'domain'
        elif related_type == 'RelatedHash':
            hash_len = len(indicator)
            if hash_len == 64:
                output_type = 'sha256'
            elif hash_len == 40:
                output_type = 'sha1'
            elif hash_len == 32:
                output_type = 'md5'
        elif related_type == 'RelatedEmailAddress':
            output_type = 'email-src'
        elif related_type == 'RelatedCyberVulnerability':
            signature = indicator.split('-')[0]
            if signature == 'CVE':
                output_type = 'vulnerability'
            elif signature == 'CWE':
                output_type = 'weakness'
        return output_type

    def get_results(self) -> dict:
        """Build and return the enrichment results."""
        self.enrichment_object.add_attribute('Enriched attribute', **self.enriched_attribute)
        for related_type, attribute in self.related_attributes:
            self.enrichment_object.add_attribute(related_type, **attribute)
        self.event.add_object(**self.enrichment_object)
        event = json.loads(self.event.to_json())
        result = {key: event[key] for key in ['Object'] if key in event}
        return {'results': result}


def handler(q=False):
    """Handle enrichment."""
    if q is False:
        return False
    request = json.loads(q)

    if request.get('config') and request['config'].get('token'):
        token = request['config'].get('token')
    else:
        misperrors['error'] = 'Missing Recorded Future token.'
        return misperrors

    input_attribute = request.get('attribute')
    rf_enricher = RFEnricher(token, input_attribute)
    try:
        rf_enricher.enrich()
    except (requests.HTTPError, KeyError):
        return misperrors

    return rf_enricher.get_results()


def introspection():
    """Returns a dict of the supported attributes."""
    return mispattributes


def version():
    """Returns a dict with the version and the associated meta-data
    including potential configurations required of the module."""
    moduleinfo['config'] = moduleconfig
    return moduleinfo
