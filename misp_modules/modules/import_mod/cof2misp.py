""" PassiveDNS Common Output Format (COF) MISP importer.

Takes as input a valid COF file or the output of the dnsdbflex utility
and creates MISP objects for the input.


Author: Aaron Kaplan
License: see LICENSE

"""

import json
import base64

import pprint
import ndjson

from pymisp import MISPObject, MISPEvent, PyMISP

from cof2misp.cof import is_valid_ip, validate_cof


misperrors = {'error': 'Error'}
userConfig = {}

inputSource = ['file']

mispattributes = {'inputSource': ['file'], 'output': ['MISP objects'],
                  'format': 'misp_standard'}


moduleinfo = {'version': '0.2', 'author': 'Aaron Kaplan',
              'description': 'Module to import the passive DNS Common Output Format (COF) and merge as a MISP objet into a MISP event.',
              'module-type': ['import']}

moduleconfig = []


# misp = PyMISP()


def parse_and_insert_cof(data: str) -> dict:
    """Parse and validate the COF data.

    Parameters
    ----------
      data as a string

    Returns
    -------
      A dict with either the error message or the data which may be sent off the the caller of handler()

    Raises
    --------
      none. All Exceptions will be handled here. On error, a misperror is returned.
    """

    objects = []
    try:
        entries = ndjson.loads(data)
        # pprint.pprint(entries)
        for l in entries:           # iterate over all ndjson lines

            # validate here (simple validation or full JSON Schema validation)
            # FIXME


            # Next, extract some fields
            rrtype = l['rrtype'].upper()
            rrname = l['rrname'].rstrip('.')
            rdata = [x.rstrip('.') for x in l['rdata']]


            # create a new MISP object, based on the passive-dns object for each nd-JSON line
            o = MISPObject(name='passive-dns', standalone=False, comment='created by cof2misp')

            # o.add_tag('tlp:amber')                                    # FIXME: we'll want to add a tlp: tag to the object
            o.add_attribute('bailiwick', value=l['bailiwick'].rstrip('.'))

            #
            # handle the combinations of rrtype (domain, ip) on both left and right side
            #

            if rrtype in ['A', 'AAAA', 'A6']:                           # address type
                # address type
                o.add_attribute('rrname_domain', value=rrname)
                for r in rdata:
                    o.add_attribute('rdata_ip', value=r)
            elif rrtype in ['CNAME', 'DNAME', 'NS']:                    # both sides are domains
                o.add_attribute('rrname_domain', value=rrname)
                for r in rdata:
                    o.add_attribute('rdata_domain', value=r)
            elif rrtype in ['SOA']:                                     # left side is a domain, right side is text
                o.add_attribute('rrname_domain', value=rrname)

            #
            # now do the regular filling up of rrname, rrtype, time_first, etc.
            #
            o.add_attribute('rrname', value=rrname)
            o.add_attribute('rrtype', value=rrtype)
            for r in rdata:
                o.add_attribute('rdata', value=r)
            o.add_attribute('raw_rdata', value=json.dumps(rdata))       # FIXME: do we need to hex encode it?
            o.add_attribute('time_first', value=l['time_first'])
            o.add_attribute('time_last', value=l['time_last'])
            o.first_seen = l['time_first']      # is this redundant?
            o.last_seen = l['time_last']

            #
            # Now add the other optional values.                        # FIXME: how about a map() other function. DNRY
            #
            for k in ['count', 'sensor_id', 'origin', 'text', 'time_first_ms', 'time_last_ms', 'zone_time_first', 'zone_time_last']:
                if k in l and l[k]:
                    o.add_attribute(k, value=l[k])

            #
            # add COF entry to MISP object
            #
            objects.append(o.to_json())

        r = {'results': {'Object': [json.loads(o) for o in objects]}}
    except Exception as ex:
        misperrors["error"] = "An error occured during parsing of input: '%s'" % (str(ex),)
        return misperrors
    return r


def parse_and_insert_dnsdbflex(data: str):
    """Parse and validate the more simplier dndsdbflex output data.

    Parameters
    ----------
      data as a string

    Returns
    -------
      A dict with either the error message or the data which may be sent off the the caller of handler()

    Raises
    --------
      none
    """
    pass            # XXX FIXME: need a MISP object for dnsdbflex



def is_dnsdbflex(data: str) -> bool:
    """Check if the supplied data conforms to the dnsdbflex output (which only contains rrname and rrtype)

    Parameters
    ----------
      ndjson data as a string

    Returns
    -------
      True or False

    Raises
    --------
      none
    """

    try:
        j = ndjson.loads(data)
        for l in j:
            if not set(l.keys()) == { 'rrname' , 'rrtype' }:
                return False            # shortcut
        return True
    except Exception as _ex:
        return False
        


def is_cof(data: str) -> bool:
    return True


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    # Parse the json, determine which type of JSON it is (dnsdbflex or COF?)
    # Validate it
    # transform into MISP object
    # push to MISP
    event_id = request['event_id']
    # event = misp.get_event(event_id)
    pprint.pprint("event_id = %s" % event_id)
    try:
        data = base64.b64decode(request["data"]).decode('utf-8')
        if not data:
            return json.dumps({'success': 0})       # empty file is ok

        if is_dnsdbflex(data):
            return parse_and_insert_dnsdbflex(data)
        elif is_cof(data):
            # check if it's valid COF format
            return parse_and_insert_cof(data)
        else:
            return {'error': 'Could not find any valid COF input nor dnsdbflex input. Please have a loot at: https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/'}
    except Exception as ex:
        print("oops, got exception %s" % str(ex))
        return {'error': "Got exception %s" % str(ex) }


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


if __name__ == '__main__':
    x = open('test.json', 'r')
    r = handler(q=x.read())
    print(json.dumps(r))
