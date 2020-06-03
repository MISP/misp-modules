import json
import logging
import sys
import os
from apiosintDS import apiosintDS

log = logging.getLogger('apiosintDS')
log.setLevel(logging.DEBUG)
apiodbg = logging.StreamHandler(sys.stdout)
apiodbg.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
apiodbg.setFormatter(formatter)
log.addHandler(apiodbg)

misperrors = {'error': 'Error'}

mispattributes = {'input': ["domain", "domain|ip", "hostname", "ip-dst", "ip-src", "ip-dst|port", "ip-src|port", "url",
                            "md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"],
                  'output': ["domain", "ip-dst", "url", "comment", "md5", "sha1", "sha256"]
                  }

moduleinfo = {'version': '0.1', 'author': 'Davide Baglieri aka davidonzo',
              'description': 'On demand query API for OSINT.digitalside.it project.',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['import_related_hashes', 'cache', 'cache_directory']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    tosubmit = []
    if request.get('domain'):
        tosubmit.append(request['domain'])
    elif request.get('domain|ip'):
        tosubmit.append(request['domain|ip'].split('|')[0])
        tosubmit.append(request['domain|ip'].split('|')[1])
    elif request.get('hostname'):
        tosubmit.append(request['hostname'])
    elif request.get('ip-dst'):
        tosubmit.append(request['ip-dst'])
    elif request.get('ip-src'):
        tosubmit.append(request['ip-src'])
    elif request.get('ip-dst|port'):
        tosubmit.append(request['ip-dst|port'].split('|')[0])
    elif request.get('ip-src|port'):
        tosubmit.append(request['ip-src|port'].split('|')[0])
    elif request.get('url'):
        tosubmit.append(request['url'])
    elif request.get('md5'):
        tosubmit.append(request['md5'])
    elif request.get('sha1'):
        tosubmit.append(request['sha1'])
    elif request.get('sha256'):
        tosubmit.append(request['sha256'])
    elif request.get('filename|md5'):
        tosubmit.append(request['filename|md5'].split('|')[1])
    elif request.get('filename|sha1'):
        tosubmit.append(request['filename|sha1'].split('|')[1])
    elif request.get('filename|sha256'):
        tosubmit.append(request['filename|sha256'].split('|')[1])
    else:
        return False

    submitcache = False
    submitcache_directory = False
    import_related_hashes = False

    r = {"results": []}

    if request.get('config'):
        if request['config'].get('cache') and request['config']['cache'].lower() == "yes":
            submitcache = True
        if request['config'].get('import_related_hashes') and request['config']['import_related_hashes'].lower() == "yes":
            import_related_hashes = True
        if submitcache:
            cache_directory = request['config'].get('cache_directory')
            if cache_directory and len(cache_directory) > 0:
                if os.access(cache_directory, os.W_OK):
                    submitcache_directory = cache_directory
                else:
                    ErrorMSG = "Cache directory is not writable. Please fix it before."
                    log.debug(str(ErrorMSG))
                    misperrors['error'] = ErrorMSG
                    return misperrors
            else:
                ErrorMSG = "Value for Plugin.Enrichment_apiosintds_cache_directory is empty but cache option is enabled as recommended. Please set a writable cache directory in plugin settings."
                log.debug(str(ErrorMSG))
                misperrors['error'] = ErrorMSG
                return misperrors
        else:
            log.debug("Cache option is set to " + str(submitcache) + ". You are not using the internal cache system and this is NOT recommended!")
            log.debug("Please, consider to turn on the cache setting it to 'Yes' and specifing a writable directory for the cache directory option.")
    try:
        response = apiosintDS.request(entities=tosubmit, cache=submitcache, cachedirectory=submitcache_directory, verbose=True)
        r["results"] += reversed(apiosintParser(response, import_related_hashes))
    except Exception as e:
        log.debug(str(e))
        misperrors['error'] = str(e)
    return r


def apiosintParser(response, import_related_hashes):
    ret = []
    if isinstance(response, dict):
        for key in response:
            for item in response[key]["items"]:
                if item["response"]:
                    comment = item["item"] + " IS listed by OSINT.digitalside.it. Date list: " + response[key]["list"]["date"]
                    if key == "url":
                        if "hashes" in item.keys():
                            if "sha256" in item["hashes"].keys():
                                ret.append({"types": ["sha256"], "values": [item["hashes"]["sha256"]]})
                            if "sha1" in item["hashes"].keys():
                                ret.append({"types": ["sha1"], "values": [item["hashes"]["sha1"]]})
                            if "md5" in item["hashes"].keys():
                                ret.append({"types": ["md5"], "values": [item["hashes"]["md5"]]})

                    if len(item["related_urls"]) > 0:
                        for urls in item["related_urls"]:
                            if isinstance(urls, dict):
                                itemToInclude = urls["url"]
                                if import_related_hashes:
                                    if "hashes" in urls.keys():
                                        if "sha256" in urls["hashes"].keys():
                                            ret.append({"types": ["sha256"], "values": [urls["hashes"]["sha256"]], "comment": "Related to: " + itemToInclude})
                                        if "sha1" in urls["hashes"].keys():
                                            ret.append({"types": ["sha1"], "values": [urls["hashes"]["sha1"]], "comment": "Related to: " + itemToInclude})
                                        if "md5" in urls["hashes"].keys():
                                            ret.append({"types": ["md5"], "values": [urls["hashes"]["md5"]], "comment": "Related to: " + itemToInclude})
                                ret.append({"types": ["url"], "values": [itemToInclude], "comment": "Related to: " + item["item"]})
                            else:
                                ret.append({"types": ["url"], "values": [urls], "comment": "Related URL to: " + item["item"]})
                else:
                    comment = item["item"] + " IS NOT listed by OSINT.digitalside.it. Date list: " + response[key]["list"]["date"]
                ret.append({"types": ["text"], "values": [comment]})
    return ret


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
