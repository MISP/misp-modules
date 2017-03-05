import json
import requests
from requests import HTTPError
import base64

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "sha512"],
                  'output': ['domain', "ip-src", "ip-dst", "text", "md5", "sha1", "sha256", "sha512", "ssdeep",
                             "authentihash", "filename"]
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '2', 'author': 'Hannah Ward',
              'description': 'Get information from virustotal',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]
limit = 5  # Default
comment = '%s: Enriched via VT'


def handler(q=False):
    global limit
    if q is False:
        return False

    q = json.loads(q)

    key = q["config"]["apikey"]
    limit = int(q["config"].get("event_limit", 5))

    r = {"results": []}

    if "ip-src" in q:
        r["results"] += getIP(q["ip-src"], key)
    if "ip-dst" in q:
        r["results"] += getIP(q["ip-dst"], key)
    if "domain" in q:
        r["results"] += getDomain(q["domain"], key)
    if 'hostname' in q:
        r["results"] += getDomain(q['hostname'], key)
    if 'md5' in q:
        r["results"] += getHash(q['md5'], key)
    if 'sha1' in q:
        r["results"] += getHash(q['sha1'], key)
    if 'sha256' in q:
        r["results"] += getHash(q['sha256'], key)
    if 'sha512' in q:
        r["results"] += getHash(q['sha512'], key)

    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
    return r


def getHash(hash, key, do_not_recurse=False):
    req = requests.get("https://www.virustotal.com/vtapi/v2/file/report",
                       params={"allinfo": 1, "apikey": key, 'resource': hash})
    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if req["response_code"] == 0:
        # Nothing found
        return []

    return getMoreInfo(req, key)


def getIP(ip, key, do_not_recurse=False):
    global limit
    toReturn = []
    req = requests.get("https://www.virustotal.com/vtapi/v2/ip-address/report",
                       params={"ip": ip, "apikey": key})
    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if req["response_code"] == 0:
        # Nothing found
        return []

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["domain"], "values": [res["hostname"]], "comment": comment % ip})
            # Pivot from here to find all domain info
            if not do_not_recurse:
                toReturn += getDomain(res["hostname"], key, True)

    toReturn += getMoreInfo(req, key)
    return toReturn


def getDomain(domain, key, do_not_recurse=False):
    global limit
    toReturn = []
    req = requests.get("https://www.virustotal.com/vtapi/v2/domain/report",
                       params={"domain": domain, "apikey": key})
    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if req["response_code"] == 0:
        # Nothing found
        return []

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["ip-dst", "ip-src"], "values": [res["ip_address"]], "comment": comment % domain})
            # Pivot from here to find all info on IPs
            if not do_not_recurse:
                toReturn += getIP(res["ip_address"], key, True)
    if "subdomains" in req:
        for subd in req["subdomains"]:
            toReturn.append({"types": ["domain"], "values": [subd], "comment": comment % domain})
    toReturn += getMoreInfo(req, key)
    return toReturn


def findAll(data, keys):
    a = []
    if isinstance(data, dict):
        for key in data.keys():
            if key in keys:
                a.append(data[key])
            else:
                if isinstance(data[key], (dict, list)):
                    a += findAll(data[key], keys)
    if isinstance(data, list):
        for i in data:
            a += findAll(i, keys)

    return a


def getMoreInfo(req, key):
    global limit
    r = []
    # Get all hashes first
    hashes = []
    hashes = findAll(req, ["md5", "sha1", "sha256", "sha512"])
    r.append({"types": ["md5", "sha1", "sha256", "sha512"], "values": hashes})
    for hsh in hashes[:limit]:
        # Search VT for some juicy info
        try:
            data = requests.get("http://www.virustotal.com/vtapi/v2/file/report",
                                params={"allinfo": 1, "apikey": key, "resource": hsh}
                                ).json()
        except:
            continue

        # Go through each key and check if it exists
        if "submission_names" in data:
            r.append({'types': ["filename"], "values": data["submission_names"], "comment": comment % hsh})

        if "ssdeep" in data:
            r.append({'types': ["ssdeep"], "values": [data["ssdeep"]], "comment": comment % hsh})

        if "authentihash" in data:
            r.append({"types": ["authentihash"], "values": [data["authentihash"]], "comment": comment % hsh})

        if "ITW_urls" in data:
            r.append({"types": ["url"], "values": data["ITW_urls"], "comment": comment % hsh})

        # Get the malware sample
        sample = requests.get("https://www.virustotal.com/vtapi/v2/file/download",
                              params={"hash": hsh, "apikey": key})

        malsample = sample.content

        # It is possible for VT to not give us any submission names
        if "submission_names" in data:
            r.append({"types": ["malware-sample"],
                      "categories": ["Payload delivery"],
                      "values": data["submission_names"],
                      "data": str(base64.b64encode(malsample), 'utf-8')
                      }
                     )

    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
