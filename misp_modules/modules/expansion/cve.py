import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'output': ['text']}
moduleinfo = {'version': '0.3', 'author': 'Alexandre Dulaunoy', 'description': 'An expansion hover module to expand information about CVE id.', 'module-type': ['hover']}
moduleconfig = ["custom_API"]
cveapi_url = 'https://cve.circl.lu/api/cve/'


def check_url(url):
    return "{}/".format(url) if not url.endswith('/') else url


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('vulnerability'):
        misperrors['error'] = 'Vulnerability id missing'
        return misperrors

    api_url = check_url(request['config']['custom_API']) if request.get('config') and request['config'].get('custom_API') else cveapi_url
    r = requests.get("{}{}".format(api_url, request.get('vulnerability')))
    if r.status_code == 200:
        vulnerability = json.loads(r.text)
        if vulnerability:
            if vulnerability.get('summary'):
                summary = vulnerability['summary']
        else:
            summary = 'Non existing CVE'
    else:
        misperrors['error'] = 'API not accessible'
        return misperrors['error']

    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
