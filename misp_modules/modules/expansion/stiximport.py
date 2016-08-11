import json
import stix
import csv
from stix.core import STIXPackage
import re
import base64

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Hannah Ward',
              'description': 'Import some stix stuff',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    q = json.loads(q)
    #Load the package up
    package = str(base64.b64decode(q.get("data", None)), 'utf-8')
    if not package:
      return json.dumps({"success":0})

    package = loadPackage(package)
    if package.observables:
      for obs in package.observables:
        r["results"].append(buildObservable(obs))
      
    return r

ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")
def buildObservable(o):
  #Life is easier with json
  o = json.loads(o.to_json())
  print(o)
  r = {"values":[]}
  props = o["object"]["properties"]
  if props["address_value"]:
    #We've got ourselves a nice little address
    value = props["address_value"]
    #Is it an IP?
    if ipre.match(value):
      #Yes!
      r["values"].append(value)
      r["types"] = ["ip-src", "ip-dst"]
    else:
      #Probably a domain yo
      r["values"].append(value)
      r["types"] = ["domain", "hostname"]

  return r

def loadPackage(data):
  #Write the stix package to a tmp file
  with open("/tmp/stixdump", "w") as f:
    f.write(data)
  try:
    try:
      package = STIXPackage().from_xml(open("/tmp/stixdump", "r"))
    except:  
      package = STIXPackage().from_json(open("/tmp/stixdump", "r"))
  except:
    print("Failed to load package")
    raise ValueError("COULD NOT LOAD STIX PACKAGE!")
  return package

def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
