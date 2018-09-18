import json
import requests
import vulners

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Igor Ivanov', 'description': 'An expansion hover module to expand information about CVE id using Vulners API.', 'module-type': ['hover']}

# Get API key from https://vulners.com/userinfo
moduleconfig = ["apikey"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('vulnerability'):
        misperrors['error'] = 'Vulnerability id missing'
        return misperrors

    key = q["config"]["apikey"]
    vulners_api = vulners.Vulners(api_key=key)
    vulners_document = vulners_api.document("CVE-2017-14174")
    if vulners_document:
        summary = vulners_document.get('description')
    else:
        summary = 'Non existing CVE'

    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
