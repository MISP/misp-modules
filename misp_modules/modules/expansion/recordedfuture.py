import json
import logging
import requests
from requests.exceptions import HTTPError, ProxyError,\
    InvalidURL, ConnectTimeout, ConnectionError
from . import check_input_attribute, checking_error, standard_error_message
import platform
import os
from urllib.parse import quote, urlparse
from pymisp import MISPAttribute, MISPEvent, MISPTag, MISPObject

moduleinfo = {
    'version': '1.0.1',
    'author': 'Recorded Future',
    'description': 'Module to retrieve data from Recorded Future',
    'module-type': ['expansion', 'hover']
}

moduleconfig = ['token', 'proxy_host', 'proxy_port', 'proxy_username', 'proxy_password']

misperrors = {'error': 'Error'}

ATTRIBUTES = [
    'ip',
    'ip-src',
    'ip-dst',
    'domain',
    'hostname',
    'md5',
    'sha1',
    'sha256',
    'uri',
    'url',
    'vulnerability',
    'weakness'
]

mispattributes = {
    'input': ATTRIBUTES,
    'output': ATTRIBUTES + ['email-src', 'text'],
    'format': 'misp_standard'
}

LOGGER = logging.getLogger('recorded_future')
LOGGER.setLevel(logging.INFO)


class RequestHandler:
    """A class for handling any outbound requests from this module."""
    def __init__(self):
        self.session = requests.Session()
        self.app_id = f'{os.path.basename(__file__)}/{moduleinfo["version"]} ({platform.platform()}) ' \
                      f'misp_enrichment/{moduleinfo["version"]} python-requests/{requests.__version__}'
        self.proxies = None
        self.rf_token = None

    def get(self, url: str, headers: dict = None) -> requests.Response:
        """General get method with proxy error handling."""
        try:
            timeout = 7 if self.proxies else None
            response = self.session.get(url, headers=headers, proxies=self.proxies, timeout=timeout)
            response.raise_for_status()
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = f'Error connecting with proxy, please check the Recorded Future app proxy settings.'
            LOGGER.error(f'{msg} Error: {error}')
            misperrors['error'] = msg
            raise

    def rf_lookup(self, category: str, ioc: str) -> requests.Response:
        """Do a lookup call using Recorded Future's ConnectAPI."""
        parsed_ioc = quote(ioc, safe='')
        url = f'https://api.recordedfuture.com/v2/{category}/{parsed_ioc}?fields=risk%2CrelatedEntities'
        headers = {'X-RFToken': self.rf_token,
                   'User-Agent': self.app_id}
        try:
            response = self.get(url, headers)
        except HTTPError as error:
            msg = f'Error when requesting data from Recorded Future. {error.response}: {error.response.reason}'
            LOGGER.error(msg)
            misperrors['error'] = msg
            raise
        return response


GLOBAL_REQUEST_HANDLER = RequestHandler()


class GalaxyFinder:
    """A class for finding MISP galaxy matches to Recorded Future data."""
    def __init__(self):
        self.session = requests.Session()
        self.sources = {
            'RelatedThreatActor': [
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json'
            ],
            'RelatedMalware': [
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/banker.json',
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/botnet.json',
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/exploit-kit.json',
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/rat.json',
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json',
                'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json'
            ]
        }
        self.galaxy_clusters = {}

    def pull_galaxy_cluster(self, related_type: str) -> None:
        """Fetches galaxy clusters for the related_type from the remote json files specified as self.sources."""
        # Only fetch clusters if not fetched previously
        if not self.galaxy_clusters.get(related_type):
            for source in self.sources.get(related_type):
                try:
                    response = GLOBAL_REQUEST_HANDLER.get(source)
                    name = source.split('/')[-1].split('.')[0]
                    self.galaxy_clusters[related_type] = {name: response.json()}
                except ConnectionError as error:
                    LOGGER.warning(f'pull_galaxy_cluster failed for source: {source}, with error: {error}.')

    def find_galaxy_match(self, indicator: str, related_type: str) -> str:
        """Searches the clusters of the related_type for a match with the indicator.
           :returns the first matching galaxy string or an empty string if no galaxy match is found.
        """
        self.pull_galaxy_cluster(related_type)
        for cluster_name, cluster in self.galaxy_clusters.get(related_type, {}).items():
            for value in cluster['values']:
                try:
                    if indicator in value['meta']['synonyms'] or indicator in value['value']:
                        value = value['value']
                        return f'misp-galaxy:{cluster_name}="{value}"'
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
    def __init__(self, attribute_props: dict):
        self.event = MISPEvent()
        self.enrichment_object = MISPObject('Recorded Future Enrichment')
        description = (
            'An object containing the enriched attribute and '
            'related entities from Recorded Future.'
        )
        self.enrichment_object.from_dict(**{
            'meta-category': 'misc',
            'description': description,
            'distribution': 0
        })

        # Create a copy of enriched attribute to add tags to
        temp_attr = MISPAttribute()
        temp_attr.from_dict(**attribute_props)
        self.enriched_attribute = MISPAttribute()
        self.enriched_attribute.from_dict(**{
            'value': temp_attr.value,
            'type': temp_attr.type,
            'distribution': 0
        })

        self.related_attributes = []
        self.color_picker = RFColors()
        self.galaxy_finder = GalaxyFinder()

        # Mapping from MISP-type to RF-type
        self.type_to_rf_category = {
            'ip': 'ip',
            'ip-src': 'ip',
            'ip-dst': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'md5': 'hash',
            'sha1': 'hash',
            'sha256': 'hash',
            'uri': 'url',
            'url': 'url',
            'vulnerability': 'vulnerability',
            'weakness': 'vulnerability'
        }

        # Related entities from RF portrayed as related attributes in MISP
        self.related_attribute_types = [
            'RelatedIpAddress', 'RelatedInternetDomainName', 'RelatedHash',
            'RelatedEmailAddress', 'RelatedCyberVulnerability'
        ]
        # Related entities from RF portrayed as tags in MISP
        self.galaxy_tag_types = ['RelatedMalware', 'RelatedThreatActor']

    def enrich(self) -> None:
        """Run the enrichment."""
        category = self.type_to_rf_category.get(self.enriched_attribute.type)
        json_response = GLOBAL_REQUEST_HANDLER.rf_lookup(category, self.enriched_attribute.value)
        response = json.loads(json_response.content)

        try:
            # Add risk score and risk rules as tags to the enriched attribute
            risk_score = response['data']['risk']['score']
            hex_color = self.color_picker.riskscore_color(risk_score)
            tag_name = f'recorded-future:risk-score="{risk_score}"'
            self.add_tag(tag_name, hex_color)
            for evidence in response['data']['risk']['evidenceDetails']:
                risk_rule = evidence['rule']
                criticality = evidence['criticality']
                hex_color = self.color_picker.riskrule_color(criticality)
                tag_name = f'recorded-future:risk-rule="{risk_rule}"'
                self.add_tag(tag_name, hex_color)

            # Retrieve related entities
            for related_entity in response['data']['relatedEntities']:
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
        except KeyError:
            misperrors['error'] = 'Unexpected format in Recorded Future api response.'
            raise

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


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format.
       If no proxy settings are set, return None."""
    proxies = None
    host = config.get('proxy_host')
    port = config.get('proxy_port')
    username = config.get('proxy_username')
    password = config.get('proxy_password')

    if host:
        if not port:
            misperrors['error'] = 'The recordedfuture_proxy_host config is set, ' \
                                  'please also set the recordedfuture_proxy_port.'
            raise KeyError
        parsed = urlparse(host)
        if 'http' in parsed.scheme:
            scheme = 'http'
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f'{netloc}:{port}'

        if username:
            if not password:
                misperrors['error'] = 'The recordedfuture_proxy_username config is set, ' \
                                      'please also set the recordedfuture_proxy_password.'
                raise KeyError
            auth = f'{username}:{password}'
            host = auth + '@' + host

        proxies = {
            'http': f'{scheme}://{host}',
            'https': f'{scheme}://{host}'
        }

    LOGGER.info(f'Proxy settings: {proxies}')
    return proxies


def handler(q=False):
    """Handle enrichment."""
    if q is False:
        return False
    request = json.loads(q)

    config = request.get('config')
    if config and config.get('token'):
        GLOBAL_REQUEST_HANDLER.rf_token = config.get('token')
    else:
        misperrors['error'] = 'Missing Recorded Future token.'
        return misperrors
    if not request.get('attribute') or not check_input_attribute(request['attribute'], requirements=('type', 'value')):
        return {'error': f'{standard_error_message}, {checking_error}.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    try:
        GLOBAL_REQUEST_HANDLER.proxies = get_proxy_settings(config)
    except KeyError:
        return misperrors

    input_attribute = request.get('attribute')
    rf_enricher = RFEnricher(input_attribute)

    try:
        rf_enricher.enrich()
    except (HTTPError, ConnectTimeout, ProxyError, InvalidURL, KeyError):
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
