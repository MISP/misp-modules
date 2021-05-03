""" PassiveDNS Common Output Format (COF) MISP importer.

Takes as input a valid COF file or the output of the dnsdbflex utility
and creates MISP objects for the input.


Author: Aaron Kaplan
License: see LICENSE

"""

import sys
import json
import base64


import ndjson

# from pymisp import MISPObject, MISPEvent, PyMISP
from pymisp import MISPObject

from cof2misp.cof import validate_cof


create_specific_attributes = False          # this is for https://github.com/MISP/misp-objects/pull/314


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
        for entry in entries:           # iterate over all ndjson lines

            # validate here (simple validation or full JSON Schema validation)
            if not validate_cof(entry):
                return {"error": "Could not validate the COF input '%s'" % entry}

            # Next, extract some fields
            rrtype = entry['rrtype'].upper()
            rrname = entry['rrname'].rstrip('.')
            rdata = [x.rstrip('.') for x in entry['rdata']]

            # create a new MISP object, based on the passive-dns object for each nd-JSON line
            o = MISPObject(name='passive-dns', standalone=False, comment='created by cof2misp')

            # o.add_tag('tlp:amber')                                    # FIXME: we'll want to add a tlp: tag to the object
            o.add_attribute('bailiwick', value=entry['bailiwick'].rstrip('.'))

            #
            # handle the combinations of rrtype (domain, ip) on both left and right side
            #

            if create_specific_attributes:
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
            o.add_attribute('time_first', value=entry['time_first'])
            o.add_attribute('time_last', value=entry['time_last'])
            o.first_seen = entry['time_first']      # is this redundant?
            o.last_seen = entry['time_last']

            #
            # Now add the other optional values.                        # FIXME: how about a map() other function. DNRY
            #
            for k in ['count', 'sensor_id', 'origin', 'text', 'time_first_ms', 'time_last_ms', 'zone_time_first', 'zone_time_last']:
                if k in entry and entry[k]:
                    o.add_attribute(k, value=entry[k])

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
    return {"error": "NOT IMPLEMENTED YET"}            # XXX FIXME: need a MISP object for dnsdbflex


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
        for line in j:
            if not set(line.keys()) == {'rrname', 'rrtype'}:
                return False            # shortcut. We assume it's not if a single line does not conform
        return True
    except Exception as ex:
        print("oops, this should not have happened. Maybe not an ndjson file? Reason: %s" % (str(ex),), file=sys.sterr)
        return False


def is_cof(data: str) -> bool:
    return True


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    # Parse the json, determine which type of JSON it is (dnsdbflex or COF?)
    # Validate it
    # transform into MISP object
    # push to MISP
    event_id = request['event_id']
    # event = misp.get_event(event_id)
    #print("event_id = %s" % event_id, file=sys.stderr)
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
        print("oops, got exception %s" % str(ex), file=sys.stderr)
        return {'error': "Got exception %s" % str(ex)}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


if __name__ == '__main__':
    x = open('test.json', 'r')
    r = handler(q=x.read())
    print(json.dumps(r))
