import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Expand Country Codes',
              'module-type': ['hover']}

# config fields that your code expects from the site admin
moduleconfig = []

common_tlds = {"com":"Commercial (Worldwide)",
               "org":"Organisation (Worldwide)",
               "net":"Network (Worldwide)",
               "int":"International (Worldwide)",
               "edu":"Education (Usually USA)",
               "gov":"Government (USA)"
              }

codes = False

def handler(q=False):
    global codes
    if not codes:
      codes = requests.get("http://www.geognos.com/api/en/countries/info/all.json").json()
    if q is False:
        return False
    request = json.loads(q)
    domain = request["domain"] if "domain" in request else request["hostname"]

    # Get the extension
    ext = domain.split(".")[-1]

    # Check if it's a common, non country one
    if ext in common_tlds.keys():
      val = common_tlds[ext]
    else:
      # Retrieve a json full of country info
      if not codes["StatusMsg"] == "OK":
        val = "Unknown"
      else:
        # Find our code based on TLD
        codes = codes["Results"]
        for code in codes.keys():
          if codes[code]["CountryCodes"]["tld"] == ext:
            val = codes[code]["Name"]
    r = {'results': [{'types':['text'], 'values':[val]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

