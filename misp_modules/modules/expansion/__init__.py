import os
import sys

sys.path.append('{}/lib'.format('/'.join((os.path.realpath(__file__)).split('/')[:-3])))

__all__ = ['cuckoo_submit', 'vmray_submit', 'bgpranking', 'circl_passivedns', 'circl_passivessl',
           'cluster25_expand', 'countrycode', 'cve', 'cve_advanced', 'cpe', 'dns', 'btc_steroids', 'domaintools',
           'eupi', 'eql', 'farsight_passivedns', 'ipasn', 'passivetotal', 'sourcecache', 'virustotal',
           'whois', 'shodan', 'reversedns', 'geoip_asn', 'geoip_city', 'geoip_country', 'wiki', 'iprep',
           'threatminer', 'otx', 'threatcrowd', 'vulndb', 'crowdstrike_falcon',
           'yara_syntax_validator', 'hashdd', 'onyphe', 'onyphe_full', 'rbl',
           'xforceexchange', 'sigma_syntax_validator', 'stix2_pattern_syntax_validator',
           'sigma_queries', 'dbl_spamhaus', 'vulners', 'yara_query', 'macaddress_io',
           'intel471', 'backscatter_io', 'btc_scam_check', 'hibp', 'greynoise', 'macvendors',
           'qrcode', 'ocr_enrich', 'pdf_enrich', 'docx_enrich', 'xlsx_enrich', 'pptx_enrich',
           'ods_enrich', 'odt_enrich', 'joesandbox_submit', 'joesandbox_query', 'urlhaus',
           'virustotal_public', 'apiosintds', 'urlscan', 'securitytrails', 'apivoid',
           'assemblyline_submit', 'assemblyline_query', 'ransomcoindb', 'malwarebazaar',
           'lastline_query', 'lastline_submit', 'sophoslabs_intelix', 'cytomic_orion', 'censys_enrich',
           'trustar_enrich', 'recordedfuture', 'html_to_markdown', 'socialscan', 'passive-ssh',
           'qintel_qsentry', 'mwdb', 'hashlookup', 'mmdb_lookup', 'ipqs_fraud_and_risk_scoring',
           'clamav', 'jinja_template_rendering','hyasinsight', 'variotdbs', 'crowdsec',
           'extract_url_components', 'ipinfo', 'whoisfreaks', 'ipgeolocation']


minimum_required_fields = ('type', 'uuid', 'value')

checking_error = 'containing at least a "type" field and a "value" field'
standard_error_message = 'This module requires an "attribute" field as input'


def check_input_attribute(attribute, requirements=minimum_required_fields):
    return all(feature in attribute for feature in requirements)
