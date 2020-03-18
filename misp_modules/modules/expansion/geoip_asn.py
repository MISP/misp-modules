import json
import geoip2.database
import sys
import logging

log = logging.getLogger('geoip_asn')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst', 'domain|ip'], 'output': ['freetext']}
moduleconfig = ['local_geolite_db']
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '0.1', 'author': 'GlennHD',
              'description': 'Query a local copy of the Maxmind Geolite ASN database (MMDB format)',
              'module-type': ['expansion', 'hover']}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get('config') or not request['config'].get('local_geolite_db'):
        return {'error': 'Please specify the path of your local copy of the Maxmind Geolite ASN database'}
    path_to_geolite = request['config']['local_geolite_db']

    if request.get('ip-dst'):
        toquery = request['ip-dst']
    elif request.get('ip-src'):
        toquery = request['ip-src']
    elif request.get('domain|ip'):
        toquery = request['domain|ip'].split('|')[1]
    else:
        return False

    try:
        reader = geoip2.database.Reader(path_to_geolite)
    except FileNotFoundError:
        return {'error': f'Unable to locate the GeoLite database you specified ({path_to_geolite}).'}
    log.debug(toquery)
    try:
        answer = reader.asn(toquery)
        stringmap = 'ASN=' + str(answer.autonomous_system_number) + ', AS Org=' + str(answer.autonomous_system_organization)
    except Exception as e:
        misperrors['error'] = f"GeoIP resolving error: {e}"
        return misperrors

    r = {'results': [{'types': mispattributes['output'], 'values': stringmap}]}

    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
