#!/usr/bin/python3

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
import re
import sys
from multiprocessing import Pool
import requests
import argparse
import string
import json

import logging
import logging.handlers
import datetime

import pymisp
from pymisp import MISPObject
from pymisp import PyMISP
from pymisp import MISPEvent


# testing
# SKIP_ORG_ID=["27"]
SKIP_ORG_ID=[]

THREADS = 4
log = None

if sys.version_info >= (3, 6, 0):
    from pymisp import ExpandedPyMISP

def splash():
    print ('MISP Build Confidence Weights')

def init(misp_url, misp_key, misp_verifycert, proxies):
    return PyMISP(misp_url, misp_key, ssl=misp_verifycert, debug=False, proxies=proxies)


def get_logger(name=None):
    root_logger_name = 'misp-confidence'

    # Build the name of the sub-logger
    if name:
        name = root_logger_name + '.' + name
    else:
        name = root_logger_name

    root_logger = logging.getLogger(root_logger_name)

    # If the root logger has no handlers, add them
    # in any case return the sub-logger
    if root_logger.handlers:
        return logging.getLogger(name)
    else:
        hdlr = logging.handlers.WatchedFileHandler(
            "misp-confidence.log")
        myAlt = AltFormatter()
        hdlr.setFormatter(myAlt)
        root_logger.addHandler(hdlr)
        root_logger.setLevel(logging.DEBUG)  # todo: make it configurable

        return logging.getLogger(name)


class AltFormatter(logging.Formatter):

    def __init__(self, msgfmt=None, datefmt=None):
        logging.Formatter.__init__(self, None, "%H:%M:%S")

    def format(self, record):
        self.converter = datetime.datetime.fromtimestamp
        ct = self.converter(record.created)
        asctime = ct.strftime("%Y-%m-%d %H:%M:%S")
        msg = record.getMessage()
        name = record.name
        if (record.levelno == logging.CRITICAL) or (record.levelno == logging.ERROR):
            record.levelname = "[E]"
        if (record.levelno == logging.WARNING):
            record.levelname = "[W]"
        if (record.levelno == logging.INFO):
            record.levelname = "[I]"
        if (record.levelno == logging.DEBUG):
            record.levelname = "[D]"
        return '%(timestamp)s: %(levelname)s %(message)s' % {'timestamp': asctime, 'levelname': record.levelname, 'message': msg}


def get_timestamp_from_attribute(attribute):
    current_timestamp = attribute['last_seen']
    if not current_timestamp:
        current_timestamp = attribute['first_seen']
    if not current_timestamp:
        current_timestamp = attribute['timestamp']

    return current_timestamp

def process_org(misp, org, current_org, total_orgs, period):
    # 1 org at a time :)

    results = None
    retry = 5
    while retry > 0:
        try:
            # results = misp.search(return_format='json', org=org['Organisation']['id'], include_sightings=1)
            results = misp.search(return_format='json', org=org['Organisation']['id'])
            break
        except Exception as e:
            retry -= 1

    if not results:
        log.error("Org %s unable to be populated." % org['Organisation']['id'])
        org_stats = { }
        org_stats[ org['Organisation']['id'] ] = { 
            'sce_s' : 0.0,
            'scr_s' : 0.0,
            'ioc_unique' : 0,
            'ioc_total' : 0,
            'scw_s' : 0.0
        }
        return org_stats

    sces_ioc_stat = 0.0
    scrs_ioc_stat = 0.0
    ioc_counter = 0
    unique_ioc_counter = 0
    log.info("Total %r events for org id %s (%r/%r)" % ( len(results), str(org['Organisation']['id']), current_org, total_orgs))
    for result in results:

        if len(result['Event']['Attribute']) == 0:
            log.warning("Event id %s has no attributes, is this correct?! %s" % ( result['Event']['id'], misp_url + "/events/view/" + result['Event']['id']) )
            with open("cache/%s.json" % result['Event']['id'], 'w') as f:
                json.dump(result, f)
            continue

        related_events = [ ]
        if 'RelatedEvent' in result['Event']:
            for e in result['Event']['RelatedEvent']:
                # print("Fetching related event: %s" % e['Event']['id'])

                # check cache!!
                if not os.path.isfile("cache/%s.json" % e['Event']['id']): 
                    related_event = misp.get_event(e['Event']['id'])
                    with open("cache/%s.json" % e['Event']['id'], 'w') as f:
                        json.dump(related_event, f)
                else:
                    with open("cache/%s.json" % e['Event']['id'], 'r') as f:
                        try:
                            related_event = json.load(f)
                        except Exception as e:
                            try:
                                os.unlink("cache/%s.json" % e['Event']['id'])
                            except:
                                pass
                            related_event = misp.get_event(e['Event']['id'])
                            with open("cache/%s.json" % e['Event']['id'], 'w') as f:
                                json.dump(related_event, f)

                related_events.append( related_event )
        # print("Total %r related events" % ( len(related_events) ) )


        # Process Objects Also!

        for attribute in result['Event']['Attribute']:
            if attribute['to_ids'] and attribute['type'] in [ 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'url', 'domain', 'domain|ip', 'hostname|ip', 'email-dst', 'email-src', 'sha1', 'md5', 'sha256', 'filename|sha1', 'filename|md5', 'filename|sha256', 'regkey|value', 'regkey' ]:
                # print("Processing attribute type: %s" % attribute['type'])
                if '|' in attribute['type']:
                    (name1, name2) = attribute['type'].split('|')
                    (value1, value2) = attribute['value'].split('|')
                    if attribute['type'][0:8] == 'filename':
                        tmp = value2
                        value2 = value1
                        value1 = tmp
                else:
                    name1 = attribute['type']
                    name2 = None
                    value1 = attribute['value']
                    value2 = None
                # print("VAL: ", value1)
                # print("VAL2: ", value2)

                """
                Timestamps of last sightings of the IoCs.
                Number of sightings per IoC. - subbing with first seen
                Description of threats related to the IoCs.
                confidence score for the IoCs provided by the intelligence feed itself - subbed since doesnt exist in any of our examples currently (nothing to reference) comment instead
                """

                n = 0
                if 'last_seen' in attribute and attribute['last_seen']:
                    n += 1
                elif 'first_seen' in attribute and attribute['first_seen']:
                    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'link':
                        # print("FOUND LINK")
                        n += 1
                        break
                #if any(artifact['type'] == 'link' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'detection-ratio':
                        # print("FOUND detection-ratio")
                        n += 1
                        break
                #if any(artifact['type'] == 'detection-ratio' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'comment':
                        # print("FOUND comment")
                        n += 1
                        break
                #if any(artifact['type'] == 'comment' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                sces_ioc_stat += ( n / 4)

                ioc_counter += 1

                # for each related event id, lookup if our current attribute val1 and 2 is present
                current_timestamp = int(get_timestamp_from_attribute(attribute))
                min_timestamp = None
                attribute_found = False
                for related_event in related_events:
                    if str(related_event['Event']['Orgc']['id']) in SKIP_ORG_ID:
                        continue
                    remote_attribute = next((sub for sub in related_event['Event']['Attribute'] if sub['type'] == name1 and sub['value'] == value1), None) 
                    if not remote_attribute:
                        for object in related_event['Event']['Object']:
                            remote_attribute = next((sub for sub in object['Attribute'] if sub['type'] == name1 and sub['value'] == value1), None) 
                            if remote_attribute:
                                break


                    if remote_attribute:
                        attribute_found = True
                        other_timestamp = get_timestamp_from_attribute(remote_attribute)

                        if other_timestamp:
                             if not min_timestamp:
                                 min_timestamp = int(other_timestamp)
                             else:
                                 min_timestamp = min( int(other_timestamp), min_timestamp  )

                if len(related_events) == 0 or not attribute_found:
                    unique_ioc_counter += 1

                if not min_timestamp:
                    min_timestamp = current_timestamp
                v = ( ( int(min_timestamp) - int(current_timestamp) ) + period ) / period
                scrs_ioc_stat += v

        for object in result['Event']['Object']:
          for attribute in object['Attribute']:
            if attribute['to_ids'] and attribute['type'] in [ 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'url', 'domain', 'domain|ip', 'hostname|ip', 'email-dst', 'email-src', 'sha1', 'md5', 'sha256', 'filename|sha1', 'filename|md5', 'filename|sha256', 'regkey|value', 'regkey' ]:
                # print("Processing attribute type: %s" % attribute['type'])
                if '|' in attribute['type']:
                    (name1, name2) = attribute['type'].split('|')
                    (value1, value2) = attribute['value'].split('|')
                    if attribute['type'][0:8] == 'filename':
                        tmp = value2
                        value2 = value1
                        value1 = tmp
                else:
                    name1 = attribute['type']
                    name2 = None
                    value1 = attribute['value']
                    value2 = None
                # print("VAL: ", value1)
                # print("VAL2: ", value2)

                """
                Timestamps of last sightings of the IoCs.
                Number of sightings per IoC. - subbing with first seen
                Description of threats related to the IoCs.
                confidence score for the IoCs provided by the intelligence feed itself - subbed since doesnt exist in any of our examples currently (nothing to reference) comment instead
                """

                n = 0
                if 'last_seen' in attribute and attribute['last_seen']:
                    n += 1
                elif 'first_seen' in attribute and attribute['first_seen']:
                    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'link':
                        # print("FOUND LINK")
                        n += 1
                        break
                #if any(artifact['type'] == 'link' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'detection-ratio':
                        # print("FOUND detection-ratio")
                        n += 1
                        break
                #if any(artifact['type'] == 'detection-ratio' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                for artifact in result['Event']['Attribute']:
                    if artifact['type'] == 'comment':
                        # print("FOUND comment")
                        n += 1
                        break
                #if any(artifact['type'] == 'comment' in artifact for artifact in result['Event']['Attribute']):
                #    n += 1

                sces_ioc_stat += ( n / 4)

                ioc_counter += 1

                # for each related event id, lookup if our current attribute val1 and 2 is present
                current_timestamp = int(get_timestamp_from_attribute(attribute))
                min_timestamp = None
                attribute_found = False
                for related_event in related_events:
                    if str(related_event['Event']['Orgc']['id']) in SKIP_ORG_ID:
                        continue
                    remote_attribute = next((sub for sub in related_event['Event']['Attribute'] if sub['type'] == name1 and sub['value'] == value1), None) 
                    if not remote_attribute:
                        for remote_object in related_event['Event']['Object']:
                            remote_attribute = next((sub for sub in remote_object['Attribute'] if sub['type'] == name1 and sub['value'] == value1), None) 
                            if remote_attribute:
                                break


                    if remote_attribute:
                        attribute_found = True
                        other_timestamp = get_timestamp_from_attribute(remote_attribute)

                        if other_timestamp:
                             if not min_timestamp:
                                 min_timestamp = int(other_timestamp)
                             else:
                                 min_timestamp = min( int(other_timestamp), min_timestamp  )

                if len(related_events) == 0 or not attribute_found:
                    unique_ioc_counter += 1

                if not min_timestamp:
                    min_timestamp = current_timestamp
                v = ( ( int(min_timestamp) - int(current_timestamp) ) + period ) / period
                scrs_ioc_stat += v
        with open("cache/%s.json" % result['Event']['id'], 'w') as f:
            json.dump(result, f)

        # print("Total iocs in event %s: %r" % ( result['Event']['id'], ioc_counter))
        if ioc_counter == 0:
            log.info("Org: %s Empty Event Id: %s" % (str(org['Organisation']['id']), result['Event']['id']))
            # log.debug(json.dumps(result))

    log.info("Total iocs for org %s (%r/%r): %r" % ( int(org['Organisation']['id']), current_org, total_orgs, ioc_counter))
    total_iocs_in_feed = ioc_counter
    if ioc_counter > 0:
        SCEs = 1.0 / ioc_counter 
        log.debug("Org: %s SCEs upper: %.f" % (str(org['Organisation']['id']), SCEs))
        log.debug("Org: %s SCEs stat: %.f" % (str(org['Organisation']['id']), sces_ioc_stat))
    else:
        log.warning("FAILED ON ORG, NO IOCS: %s" % str(org['Organisation']['id']))
        SCEs = 0

    org_stats = { }
    org_stats[ org['Organisation']['id'] ] = { 
        'sce_s' : SCEs * sces_ioc_stat,
        'scr_s' : SCEs * scrs_ioc_stat,
        'ioc_unique' : unique_ioc_counter,
        'ioc_total' : ioc_counter,
        'scw_s' : 0
    }

    log.debug(json.dumps(org_stats[ org['Organisation']['id'] ]))
    return org_stats

    

if __name__ == '__main__':

    log = get_logger()
    splash()
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--clear", help="Clear local cache before processing.", action='store_true')
    parser.add_argument("-t", "--time", help="Number of hours before data is stale.")
    parser.add_argument("-o", "--output", help="Output file to store weights json.")
    parser.add_argument("-w", "--workers", help="Number of workers in pool, default is 4.")
    parser.add_argument("-i", "--disablessl", help="Disable ssl checks.", action='store_true')
    parser.add_argument("-m", "--mispurl", help="Base MISP URL.")
    parser.add_argument("-k", "--mispauthkey", help="MISP Authkey")

    args = parser.parse_args()

    if not args.mispurl:
        print("No --mispurl provided, failling")
        sys.exit(1)

    if not args.mispauthkey:
        print("No --mispauthkey provided, failling")
        sys.exit(1)

    misp_url = args.mispurl
    misp_key = args.mispauthkey

    if args.workers:
        THREADS = int(args.workers)

    if args.time:
        hours = int(args.time)
    else:
        hours = 14*24

    output_file = '/var/tmp/misp-source-confidence.json'
    if args.output:
        output_file = args.output

    # make/clear our cache
    if not os.path.isdir("cache"):
        os.mkdir("cache")
    if args.clear:
        filelist = [ f for f in os.listdir("cache") if f.endswith(".json") ]
        for f in filelist:
            os.remove(os.path.join("cache", f))

    # no proxy support built in, sorry, add me later
    misp = init(misp_url, misp_key, not args.disablessl, { })

    orgs = misp.organisations(scope='all') # or maybe just 'external'

    # xxx: implement allow list detection

    period = hours * (3600)

    org_stats_extensiveness = { }

    total_orgs = len(orgs)
    current_org = 0
    total_iocs = 0
    unique_ioc_counter = 0

    pool = Pool(THREADS)
    results = []

    for org in orgs:
        current_org += 1
        if not str(org['Organisation']['id']) in SKIP_ORG_ID: 
            results.append(pool.apply_async(process_org, args=(misp, org, current_org, total_orgs, period)))
        else:
            log.info("Skipping organization: %s" %  str(org['Organisation']['id']) )

        # for testing only
        #if current_org >= 5:
        #    break

    pool.close()
    pool.join()
    results = [r.get() for r in results]

    for x in results:
        org_stats_extensiveness.update(x)

    # print(org_stats_extensiveness)
    for org in org_stats_extensiveness.keys():
        unique_ioc_counter += org_stats_extensiveness[org]['ioc_unique']
        total_iocs += org_stats_extensiveness[org]['ioc_total']


    # FINISH CALCULATED scc_s
    for org in org_stats_extensiveness.keys():
        if unique_ioc_counter > 0: 
            org_stats_extensiveness[org]['scc_s'] =  org_stats_extensiveness[org]['ioc_total'] / unique_ioc_counter
        else:
            org_stats_extensiveness[org]['scc_s'] = 0


        weight_SCE = 1
        weight_SCR = 1
        weight_SCC = 1
        weight_SCW = 1

        # total score confidence for org
        org_stats_extensiveness[org]['scs'] = (  ( weight_SCE * org_stats_extensiveness[org]['sce_s'] ) +  ( weight_SCR * org_stats_extensiveness[org]['scr_s'] ) + \
             ( weight_SCC * org_stats_extensiveness[org]['scc_s'] ) + ( weight_SCW * org_stats_extensiveness[org]['scw_s'] ) / ( weight_SCE + weight_SCR + weight_SCC + weight_SCW ) )

        weight_SCE = 1
        weight_SCR = 1
        weight_SCC = 0
        weight_SCW = 1

        # total score confidence for org
        org_stats_extensiveness[org]['scs0'] = (  ( weight_SCE * org_stats_extensiveness[org]['sce_s'] ) +  ( weight_SCR * org_stats_extensiveness[org]['scr_s'] ) + \
             ( weight_SCC * org_stats_extensiveness[org]['scc_s'] ) + ( weight_SCW * org_stats_extensiveness[org]['scw_s'] ) / ( weight_SCE + weight_SCR + weight_SCC + weight_SCW ) )


        weight_SCE = 0.8
        weight_SCR = 0.6
        weight_SCC = 0
        weight_SCW = 1

        # total score confidence for org
        org_stats_extensiveness[org]['scs3'] = (  ( weight_SCE * org_stats_extensiveness[org]['sce_s'] ) +  ( weight_SCR * org_stats_extensiveness[org]['scr_s'] ) + \
             ( weight_SCC * org_stats_extensiveness[org]['scc_s'] ) + ( weight_SCW * org_stats_extensiveness[org]['scw_s'] ) / ( weight_SCE + weight_SCR + weight_SCC + weight_SCW ) )

    print("GOLDEN TABLE")
    print(json.dumps(org_stats_extensiveness))
    log.info("GOLDEN TABLE")
    log.info(json.dumps(org_stats_extensiveness))

    with open(output_file, 'w') as f:
        f.write(json.dumps(org_stats_extensiveness))

