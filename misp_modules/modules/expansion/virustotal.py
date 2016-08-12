import json
import requests
import hashlib
import re
import base64

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', "ip-src", "ip-dst"],
                  'output':['domain', "ip-src", "ip-dst", "text"]
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Get information from virustotal',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]


def handler(q=False):
    if q is False:
        return False

    q = json.loads(q)

    key = q["config"]["apikey"]

    r = {"results": []}
    
    if "ip-src" in q:
      r["results"] += getIP(q["ip-src"], key)
    if "ip-dst" in q:
      r["results"] += getIP(q["ip-dst"], key)
    if "domain" in q:
      r["results"] += getDomain(q["domain"], key)

  
    return r

def getIP(ip, key):
    toReturn = []
    req = requests.get("https://www.virustotal.com/vtapi/v2/ip-address/report", 
                       params = {"ip":ip, "apikey":key}
                      ).json()
    if req["response_code"] == 0:
      #Nothing found
      return []
    
    if "resolutions" in req:
      for res in req["resolutions"]:
        toReturn.append( {"types":["domain"], "values":[res["hostname"]]})

    toReturn += getMoreInfo(req, key)
    return toReturn
    
def getDomain(ip, key):
    toReturn = []
    req = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", 
                       params = {"domain":ip, "apikey":key}
                      ).json()
    if req["response_code"] == 0:
      #Nothing found
      return []
    
    if "resolutions" in req:
      for res in req["resolutions"]:
        toReturn.append( {"types":["ip-dst", "ip-src"], "values":[res["ip_address"]]})

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
    r = []
    #Get all hashes first
    hashes = []
    hashes = findAll(req, ["md5", "sha1", "sha256", "sha512"])
    r.append({"types":["md5", "sha1", "sha256", "sha512"], "values":hashes})
    for hsh in hashes:
      #Search VT for some juicy info
      data = requests.get("http://www.virustotal.com/vtapi/v2/file/report",
                          params={"allinfo":1, "apikey":key, "resource":hsh}
                         ).json()
      if "submission_names" in data:
        r.append({'types':["filename"], "values":data["submission_names"]})

      if "ssdeep" in data:
        r.append({'types':["ssdeep"], "values":[data["ssdeep"]]})

      if "authentihash" in data:
        r.append({"types":["authentihash"], "values":[data["authentihash"]]})

      if "ITW_urls" in data:
        r.append({"types":["url"], "values":data["ITW_urls"]})

      #Get the malware sample
      sample = requests.get("https://www.virustotal.com/vtapi/v2/file/download",
                            params = {"hash":hsh, "apikey":key})
      r.append({'types':['malware-sample'], 'values':[str(base64.b64encode(sample.content), 'utf-8')]})
    return r

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

