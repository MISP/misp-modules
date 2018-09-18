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

    key = request['config'].get('apikey')
    vulners_api = vulners.Vulners(api_key=key)
    vulners_document = vulners_api.document(request.get('vulnerability'))
    vulners_exploits = vulners_api.searchExploit(request.get('vulnerability'))
    if vulners_document:
        summary = vulners_document.get('description')
    else:
        summary = 'Non existing CVE'

    if vulners_exploits:
        for exploit in vulners_exploits[0]:
            exploit_summary += exploit['title'] + " " + exploit['href'] + "\n"
        summary +=  vulners_exploits[1] + " Public exploits available:\n " + exploit_summary


    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
