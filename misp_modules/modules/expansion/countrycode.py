import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Expand Country Codes',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = []

common_tlds = {"com":"Commercial (Worldwide)",
               "org":"Organisation (Worldwide)",
               "net":"Network (Worldwide)",
               "int":"International (Worldwide)",
               "edu":"Education (Usually USA)",
               "gov":"Government (USA)"
              }

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    domain = request["domain"]

    # Get the extension
    ext = domain.split(".")[-1]

    # Check if if's a common, non country one 
    if ext in common_tlds.keys():
      val = common_tlds[ext]
    else:
      # Retrieve a json full of country info
      codes = requests.get("http://www.geognos.com/api/en/countries/info/all.json").json()

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

