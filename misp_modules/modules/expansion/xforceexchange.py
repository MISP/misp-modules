import requests
import json
import sys

BASEurl = "https://api.xforce.ibmcloud.com/"

extensions = {"ip1": "ipr/%s",
	      "ip2": "ipr/malware/%s",
	      "url": "url/%s",
	      "hash": "malware/%s",
	      "vuln": "/vulnerabilities/search/%s",
	      "dns": "resolve/%s"}

sys.path.append('./')

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst', 'vulnerability', 'md5', 'sha1', 'sha256'], 
		  'output': ['ip-src', 'ip-dst', 'text', 'domain']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Joerg Stephan (@johest)',
              'description': 'IBM X-Force Exchange expansion module',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]
limit = 5000 #Default



def MyHeader(key=False):
	global limit
	if key is False:
		return None
	
	return {"Authorization": "Basic %s " % key,
		   "Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}

def handler(q=False):
	global limit
	if q is False:
		return False

	q = json.loads(q)
	
	key = q["config"]["apikey"]
	limit = int(q["config"].get("event_limit", 5))

	r = {"results": []}
	
	if "ip-src" in q:
		r["results"] += apicall("dns", q["ip-src"], key)
	if "ip-dst" in q:
		r["results"] += apicall("dns", q["ip-dst"], key)
	if "md5" in q:
		r["results"] += apicall("hash", q["md5"], key)
	if "sha1" in q:
		r["results"] += apicall("hash", q["sha1"], key)
	if "sha256" in q:
		r["results"] += apicall("hash", q["sha256"], key)  
	if 'vulnerability' in q:
		r["results"] += apicall("vuln", q["vulnerability"], key)
	if "domain" in q:
                r["results"] += apicall("dns", q["domain"], key)

	uniq = []
	for res in r["results"]:
		if res not in uniq:
			uniq.append(res)
	r["results"] = uniq
	return r
	
def apicall(indicator_type, indicator, key=False):
	try:
		myURL = BASEurl + (extensions[str(indicator_type)])%indicator
		jsondata = requests.get(myURL, headers=MyHeader(key)).json()
	except:
		jsondata = None
	redata = []
	#print(jsondata)
	if not jsondata is None:
		if indicator_type is "hash":
			if "malware" in jsondata:
				lopointer = jsondata["malware"]
				redata.append({"type": "text", "values": lopointer["risk"]})
		if indicator_type is "dns":
			if "records" in str(jsondata):
				lopointer = jsondata["Passive"]["records"]
				for dataset in lopointer:
					redata.append({"type":"domain", "values": dataset["value"]})	
	
	return redata

def introspection():
	return mispattributes


def version():
	moduleinfo['config'] = moduleconfig
	return moduleinfo
