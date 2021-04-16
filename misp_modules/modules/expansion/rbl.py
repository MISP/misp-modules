import json
import sys

try:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.2
    resolver.lifetime = 0.2
except ImportError:
    print("dnspython3 is missing, use 'pip install dnspython3' to install it.")
    sys.exit(0)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'output': ['text']}
moduleinfo = {'version': '0.2', 'author': 'Christian Studer',
              'description': 'Check an IPv4 address against known RBLs.',
              'module-type': ['expansion', 'hover']}
moduleconfig = []

rbls = (
    "spam.spamrats.com",
    "spamguard.leadmon.net",
    "rbl-plus.mail-abuse.org",
    "web.dnsbl.sorbs.net",
    "ix.dnsbl.manitu.net",
    "virus.rbl.jp",
    "dul.dnsbl.sorbs.net",
    "bogons.cymru.com",
    "psbl.surriel.com",
    "misc.dnsbl.sorbs.net",
    "httpbl.abuse.ch",
    "combined.njabl.org",
    "smtp.dnsbl.sorbs.net",
    "korea.services.net",
    "drone.abuse.ch",
    "rbl.efnetrbl.org",
    "cbl.anti-spam.org.cn",
    "b.barracudacentral.org",
    "bl.spamcannibal.org",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
    "rbl.suresupport.com",
    "db.wpbl.info",
    "sbl.spamhaus.org",
    "http.dnsbl.sorbs.net",
    "csi.cloudmark.com",
    "rbl.interserver.net",
    "ubl.unsubscore.com",
    "dnsbl.sorbs.net",
    "virbl.bit.nl",
    "pbl.spamhaus.org",
    "socks.dnsbl.sorbs.net",
    "short.rbl.jp",
    "dnsbl.dronebl.org",
    "blackholes.mail-abuse.org",
    "truncate.gbudb.net",
    "dyna.spamrats.com",
    "spamrbl.imp.ch",
    "spam.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "query.senderbase.org",
    "opm.tornevall.org",
    "netblock.pedantic.org",
    "access.redhawk.org",
    "cdl.anti-spam.org.cn",
    "multi.surbl.org",
    "noptr.spamrats.com",
    "dnsbl.inps.de",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "dsn.rfc-ignorant.org",
    "zombie.dnsbl.sorbs.net",
    "dnsbl.njabl.org",
    "relays.mail-abuse.org",
    "rbl.spamlab.com",
    "all.bl.blocklist.de"
)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('ip-src'):
        ip = request['ip-src']
    elif request.get('ip-dst'):
        ip = request['ip-dst']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    infos = {}
    ipRev = '.'.join(ip.split('.')[::-1])
    for rbl in rbls:
        query = '{}.{}'.format(ipRev, rbl)
        try:
            txt = resolver.query(query, 'TXT')
            infos[query] = [str(t) for t in txt]
        except Exception:
            continue
    result = "\n".join([f"{rbl}: {'  -  '.join(info)}" for rbl, info in infos.items()])
    if not result:
        return {'error': 'No data found by querying known RBLs'}
    return {'results': [{'types': mispattributes.get('output'), 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
