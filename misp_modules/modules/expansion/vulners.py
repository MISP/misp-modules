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

    ai_summary = ''
    exploit_summary = ''
    vuln_summary = ''

    key = request['config'].get('apikey')
    vulners_api = vulners.Vulners(api_key=key)
    vulnerability = request.get('vulnerability')
    vulners_document = vulners_api.document(vulnerability)
    vulners_exploits = vulners_api.searchExploit(vulnerability)
    vulners_ai_score = vulners_api.aiScore(vulnerability)

    if vulners_document:
        vuln_summary += vulners_document.get('description')
    else:
        vuln_summary += 'Non existing CVE'

    if vulners_ai_score:
        ai_summary += 'Vulners AI Score is ' + str(vulners_ai_score[0]) + " "

    if vulners_exploits:
        exploit_summary += " ||  " + str(len(vulners_exploits[0])) + " Public exploits available:\n  "
        for exploit in vulners_exploits[0]:
            exploit_summary += exploit['title'] + " " + exploit['href'] + "\n  "
        exploit_summary +=  "|| Vulnerability Description:  " + vuln_summary
    
    summary = ai_summary + exploit_summary + vuln_summary    
    
    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
