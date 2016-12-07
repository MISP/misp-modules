import json, pygeoip
import sys, logging
import configparser

log = logging.getLogger('geoip_country')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst', 'domain|ip'], 'output': ['freetext']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '0.1', 'author': 'Andreas Muehlemann',
              'description': 'Query a local copy of Maxminds Geolite database',
              'module-type': ['expansion', 'hover']}

# get current db from http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
config = configparser.ConfigParser()
config.read('geoip_country.cfg')
gi = pygeoip.GeoIP(config.get('GEOIP', 'database'))

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if request.get('ip-dst'):
        toquery = request['ip-dst']
    elif request.get('ip-src'):
        toquery = request['ip-src']
    elif request.get('domain|ip'):
        toquery = request['domain|ip'].split('|')[1]
    else:
        return false

    log.debug(toquery)

    try:
        answer = gi.country_code_by_addr(toquery)
    except:
        misperrors['error'] = "GeoIP resolving error"
        return misperrors

    r = {'results': [{'types': mispattributes['output'],
                      'values': [str(answer)]}]}

    return r

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
