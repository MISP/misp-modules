# encoding: utf-8
import json
import base64
import codecs
from dateutil.parser import isoparse
from pymisp import MISPAttribute, MISPEvent, MISPObject
try:
    import censys.base
    import censys.ipv4
    import censys.websites
    import censys.certificates
except ImportError:
    print("Censys module not installed. Try 'pip install censys'")

misperrors = {'error': 'Error'}
moduleconfig = ['api_id', 'api_secret']
mispattributes = {'input': ['ip-src', 'ip-dst', 'domain', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'Loïc Fortemps',
              'description': 'Censys.io expansion module', 'module-type': ['expansion', 'hover']}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if request.get('config'):
        if (request['config'].get('api_id') is None) or (request['config'].get('api_secret') is None):
            misperrors['error'] = "Censys API credentials are missing"
            return misperrors
    else:
        misperrors['error'] = "Please provide config options"
        return misperrors

    api_id = request['config']['api_id']
    api_secret = request['config']['api_secret']

    if not request.get('attribute'):
        return {'error': 'Unsupported input.'}
    attribute = request['attribute']
    if not any(input_type == attribute['type'] for input_type in mispattributes['input']):
        return {'error': 'Unsupported attributes type'}

    attribute = MISPAttribute()
    attribute.from_dict(**request['attribute'])

    if attribute.type == 'ip-dst' or attribute.type == 'ip-src':
        conn = censys.ipv4.CensysIPv4(api_id=api_id, api_secret=api_secret)
    elif attribute.type == 'domain':
        conn = censys.websites.CensysWebsites(api_id=api_id, api_secret=api_secret)
    elif 'x509-fingerprint' in attribute.type:
        conn = censys.certificates.CensysCertificates(api_id=api_id, api_secret=api_secret)
    else:
        return False

    try:
        result = conn.view(attribute.value)
    except censys.base.CensysNotFoundException:
        misperrors['error'] = "Nothing could be found on Censys"
        return misperrors
    except Exception:
        misperrors['error'] = "Connection issue"
        return misperrors

    r = {'results': parse_response(result, attribute)}
    return r


def parse_response(censys_output, attribute):
    misp_event = MISPEvent()
    misp_event.add_attribute(**attribute)
    # Generic fields (for IP/Websites)
    if "autonomous_system" in censys_output:
        cen_as = censys_output['autonomous_system']
        asn_object = MISPObject('asn')
        asn_object.add_attribute('asn', value=cen_as["asn"])
        asn_object.add_attribute('description', value=cen_as['name'])
        asn_object.add_attribute('subnet-announced', value=cen_as['routed_prefix'])
        asn_object.add_attribute('country', value=cen_as['country_code'])
        asn_object.add_reference(attribute.uuid, 'associated-to')
        misp_event.add_object(**asn_object)

    if "ip" in censys_output and "ports" in censys_output:
        ip_object = MISPObject('ip-port')
        ip_object.add_attribute('ip', value=censys_output['ip'])
        for p in censys_output['ports']:
            ip_object.add_attribute('dst-port', value=p)
        ip_object.add_reference(attribute.uuid, 'associated-to')
        misp_event.add_object(**ip_object)

    # We explore all ports to find https or ssh services
    for k in censys_output.keys():
        if not isinstance(censys_output[k], dict):
            continue
        if 'https' in censys_output[k]:
            try:
                cert = censys_output[k]['https']['tls']['certificate']
                cert_obj = get_certificate_object(cert, attribute)
                misp_event.add_object(**cert_obj)
            except KeyError:
                print("Error !")
        if 'ssh' in censys_output[k]:
            try:
                cert = censys_output[k]['ssh']['v2']['server_host_key']
                # To enable once the type is merged
                # misp_event.add_attribute(type='hasshserver-sha256', value=cert['fingerprint_sha256'])
            except KeyError:
                pass

    # Info from certificate query
    if "parsed" in censys_output:
        cert_obj = get_certificate_object(censys_output, attribute)
        misp_event.add_object(**cert_obj)

    # Location can be present for IP/Websites results
    if "location" in censys_output:
        loc_obj = MISPObject('geolocation')
        loc = censys_output['location']
        loc_obj.add_attribute('latitude', value=loc['latitude'])
        loc_obj.add_attribute('longitude', value=loc['longitude'])
        loc_obj.add_attribute('city', value=loc['city'])
        loc_obj.add_attribute('country', value=loc['country'])
        loc_obj.add_attribute('zipcode', value=loc['postal_code'])
        if 'province' in loc:
            loc_obj.add_attribute('region', value=loc['province'])
        loc_obj.add_reference(attribute.uuid, 'associated-to')
        misp_event.add_object(**loc_obj)

    event = json.loads(misp_event.to_json())
    return {'Object': event['Object'], 'Attribute': event['Attribute']}


def get_certificate_object(cert, attribute):
    parsed = cert['parsed']
    cert_object = MISPObject('x509')
    cert_object.add_attribute('x509-fingerprint-sha256', value=parsed['fingerprint_sha256'])
    cert_object.add_attribute('x509-fingerprint-sha1', value=parsed['fingerprint_sha1'])
    cert_object.add_attribute('x509-fingerprint-md5', value=parsed['fingerprint_md5'])
    cert_object.add_attribute('serial-number', value=parsed['serial_number'])
    cert_object.add_attribute('version', value=parsed['version'])
    cert_object.add_attribute('subject', value=parsed['subject_dn'])
    cert_object.add_attribute('issuer', value=parsed['issuer_dn'])
    cert_object.add_attribute('validity-not-before', value=isoparse(parsed['validity']['start']))
    cert_object.add_attribute('validity-not-after', value=isoparse(parsed['validity']['end']))
    cert_object.add_attribute('self_signed', value=parsed['signature']['self_signed'])
    cert_object.add_attribute('signature_algorithm', value=parsed['signature']['signature_algorithm']['name'])

    cert_object.add_attribute('pubkey-info-algorithm', value=parsed['subject_key_info']['key_algorithm']['name'])

    if 'rsa_public_key' in parsed['subject_key_info']:
        pub_key = parsed['subject_key_info']['rsa_public_key']
        cert_object.add_attribute('pubkey-info-size', value=pub_key['length'])
        cert_object.add_attribute('pubkey-info-exponent', value=pub_key['exponent'])
        hex_mod = codecs.encode(base64.b64decode(pub_key['modulus']), 'hex').decode()
        cert_object.add_attribute('pubkey-info-modulus', value=hex_mod)

    if "extensions" in parsed and "subject_alt_name" in parsed["extensions"]:
        san = parsed["extensions"]["subject_alt_name"]
        if "dns_names" in san:
            for dns in san['dns_names']:
                cert_object.add_attribute('dns_names', value=dns)
        if "ip_addresses" in san:
            for ip in san['ip_addresses']:
                cert_object.add_attribute('ip', value=ip)

    if "raw" in cert:
        cert_object.add_attribute('raw-base64', value=cert['raw'])

    cert_object.add_reference(attribute.uuid, 'associated-to')
    return cert_object


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
