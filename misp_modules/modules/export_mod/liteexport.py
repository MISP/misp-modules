import json
import base64

misperrors = {'error': 'Error'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 
			'author': 'TM',
			'description': 'export lite',
			'module-type': ['export']}

# config fields that your code expects from the site admin
moduleconfig = ["indent_json_export"]

#~ mispattributes = {'input':'all'} ?
mispattributes = {}
outputFileExtension = "json"
responseType = "application/json"

def handler(q=False):
	if q is False:
		return False
	request = json.loads(q)
	if "config" in request:
		config  = request["config"]
	else:
		config  = {"indent_json_export":None}

	if 'data' not in request:
		return False

	liteEvent = {'Event':{}}

	for evt in request['data']:
		rawEvent = evt['Event']
		liteEvent['Event']['info'] = rawEvent['info']
		liteEvent['Event']['Attribute'] = []
		
		attrs = evt['Attribute']
		for attr in attrs:
			liteAttr = {}
			liteAttr['category'] = attr['category']
			liteAttr['type'] = attr['type']
			liteAttr['value'] = attr['value']
			liteEvent['Event']['Attribute'].append(liteAttr)

	return {"response":[],
			'data': str(base64.b64encode(
				bytes(
					json.dumps(liteEvent, indent=config['indent_json_export']),
					'utf-8')),
				'utf-8')
			}

def introspection():
	modulesetup = {}
	try:
		responseType
		modulesetup['responseType'] = responseType
	except NameError:
	  pass
	try:
		userConfig
		modulesetup['userConfig'] = userConfig
	except NameError:
		pass
	try:
		outputFileExtension
		modulesetup['outputFileExtension'] = outputFileExtension
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
