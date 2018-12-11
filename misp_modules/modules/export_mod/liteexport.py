import json
import base64

misperrors = {'error': 'Error'}

moduleinfo = {'version': '1',
              'author': 'TM',
              'description': 'export lite',
              'module-type': ['export']}

moduleconfig = ["indent_json_export"]

mispattributes = {}
outputFileExtension = "json"
responseType = "application/json"


def handler(q=False):
        if q is False:
                return False

        request = json.loads(q)

        config = {}
        if "config" in request:
                config = request["config"]
        else:
                config = {"indent_json_export": None}

        if config['indent_json_export'] is not None:
                try:
                        config['indent_json_export'] = int(config['indent_json_export'])
                except Exception:
                        config['indent_json_export'] = None

        if 'data' not in request:
                return False

        # ~ Misp json structur
        liteEvent = {'Event': {}}

        for evt in request['data']:
                rawEvent = evt['Event']
                liteEvent['Event']['info'] = rawEvent['info']
                liteEvent['Event']['Attribute'] = []

                attrs = evt['Attribute']
                for attr in attrs:
                        if 'Internal reference' not in attr['category']:
                                liteAttr = {}
                                liteAttr['category'] = attr['category']
                                liteAttr['type'] = attr['type']
                                liteAttr['value'] = attr['value']
                                liteEvent['Event']['Attribute'].append(liteAttr)

        return {'response': [],
                'data': str(base64.b64encode(bytes(
                    json.dumps(liteEvent, indent=config['indent_json_export']), 'utf-8')), 'utf-8')}


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
