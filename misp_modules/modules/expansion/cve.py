import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'output': ['text']}
moduleinfo = {
    'version': '0.4',
    'author': 'Alexandre Dulaunoy',
    'description': 'An expansion hover module to expand information about CVE id.',
    'module-type': ['hover'],
    'name': 'CVE Lookup',
    'logo': 'cve.png',
    'requirements': [],
    'features': 'The module takes a vulnerability attribute as input and queries the CIRCL CVE search API to get information about the vulnerability as it is described in the list of CVEs.',
    'references': ['https://vulnerability.circl.lu/', 'https://cve.mitre.org/'],
    'input': 'Vulnerability attribute.',
    'output': 'Text giving information about the CVE related to the Vulnerability.',
}
moduleconfig = ["custom_API"]
cveapi_url = 'https://vulnerability.circl.lu/api/cve/'


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
        try:
            summary = vulnerability['containers']['cna']['descriptions'][0]['value']
        except Exception:
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
