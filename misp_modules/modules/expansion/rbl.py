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
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Check an IPv4 address against known RBLs.',
              'module-type': ['expansion', 'hover']}
moduleconfig = []

rbls = {
    'spam.spamrats.com': 'http://www.spamrats.com',
    'spamguard.leadmon.net': 'http://www.leadmon.net/SpamGuard/',
    'rbl-plus.mail-abuse.org': 'http://www.mail-abuse.com/lookup.html',
    'web.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'ix.dnsbl.manitu.net': 'http://www.dnsbl.manitu.net',
    'virus.rbl.jp': 'http://www.rbl.jp',
    'dul.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'bogons.cymru.com': 'http://www.team-cymru.org/Services/Bogons/',
    'psbl.surriel.com': 'http://psbl.surriel.com',
    'misc.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'httpbl.abuse.ch': 'http://dnsbl.abuse.ch',
    'combined.njabl.org': 'http://combined.njabl.org',
    'smtp.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'korea.services.net': 'http://korea.services.net',
    'drone.abuse.ch': 'http://dnsbl.abuse.ch',
    'rbl.efnetrbl.org': 'http://rbl.efnetrbl.org',
    'cbl.anti-spam.org.cn': 'http://www.anti-spam.org.cn/?Locale=en_US',
    'b.barracudacentral.org': 'http://www.barracudacentral.org/rbl/removal-request',
    'bl.spamcannibal.org': 'http://www.spamcannibal.org',
    'xbl.spamhaus.org': 'http://www.spamhaus.org/xbl/',
    'zen.spamhaus.org': 'http://www.spamhaus.org/zen/',
    'rbl.suresupport.com': 'http://suresupport.com/postmaster',
    'db.wpbl.info': 'http://www.wpbl.info',
    'sbl.spamhaus.org': 'http://www.spamhaus.org/sbl/',
    'http.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'csi.cloudmark.com': 'http://www.cloudmark.com/en/products/cloudmark-sender-intelligence/index',
    'rbl.interserver.net': 'http://rbl.interserver.net',
    'ubl.unsubscore.com': 'http://www.lashback.com/blacklist/',
    'dnsbl.sorbs.net': 'http://www.sorbs.net',
    'virbl.bit.nl': 'http://virbl.bit.nl',
    'pbl.spamhaus.org': 'http://www.spamhaus.org/pbl/',
    'socks.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'short.rbl.jp': 'http://www.rbl.jp',
    'dnsbl.dronebl.org': 'http://www.dronebl.org',
    'blackholes.mail-abuse.org': 'http://www.mail-abuse.com/lookup.html',
    'truncate.gbudb.net': 'http://www.gbudb.com/truncate/index.jsp',
    'dyna.spamrats.com': 'http://www.spamrats.com',
    'spamrbl.imp.ch': 'http://antispam.imp.ch',
    'spam.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'wormrbl.imp.ch': 'http://antispam.imp.ch',
    'query.senderbase.org': 'http://www.senderbase.org/about',
    'opm.tornevall.org': 'http://dnsbl.tornevall.org',
    'netblock.pedantic.org': 'http://pedantic.org',
    'access.redhawk.org': 'http://www.redhawk.org/index.php?option=com_wrapper&Itemid=33',
    'cdl.anti-spam.org.cn': 'http://www.anti-spam.org.cn/?Locale=en_US',
    'multi.surbl.org': 'http://www.surbl.org',
    'noptr.spamrats.com': 'http://www.spamrats.com',
    'dnsbl.inps.de': 'http://dnsbl.inps.de/index.cgi?lang=en',
    'bl.spamcop.net': 'http://bl.spamcop.net',
    'cbl.abuseat.org': 'http://cbl.abuseat.org',
    'dsn.rfc-ignorant.org': 'http://www.rfc-ignorant.org/policy-dsn.php',
    'zombie.dnsbl.sorbs.net': 'http://www.sorbs.net',
    'dnsbl.njabl.org': 'http://dnsbl.njabl.org',
    'relays.mail-abuse.org': 'http://www.mail-abuse.com/lookup.html',
    'rbl.spamlab.com': 'http://tools.appriver.com/index.aspx?tool=rbl',
    'all.bl.blocklist.de': 'http://www.blocklist.de/en/rbldns.html'
}


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
    listeds = []
    infos = []
    ipRev = '.'.join(ip.split('.')[::-1])
    for rbl in rbls:
        query = '{}.{}'.format(ipRev, rbl)
        try:
            txt = resolver.query(query, 'TXT')
            listeds.append(query)
            infos.append([str(t) for t in txt])
        except Exception:
            continue
    result = "\n".join([f"{listed}: {'  -  '.join(info)}" for listed, info in zip(listeds, infos)])
    if not result:
        return {'error': 'No data found by querying known RBLs'}
    return {'results': [{'types': mispattributes.get('output'), 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
