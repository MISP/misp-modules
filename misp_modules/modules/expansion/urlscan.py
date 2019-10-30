import json
import requests
import logging
import sys
import time

log = logging.getLogger('urlscan')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

moduleinfo = {
    'version': '0.1',
    'author': 'Dave Johnson',
    'description': 'Module to query urlscan.io',
    'module-type': ['expansion']
}

moduleconfig = ['apikey']
misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url'],
    'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url', 'text', 'link', 'hash']
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'Urlscan apikey is missing'
        return misperrors
    client = urlscanAPI(request['config']['apikey'])

    r = {'results': []}

    if 'ip-src' in request:
        r['results'] += lookup_indicator(client, request['ip-src'])
    if 'ip-dst' in request:
        r['results'] += lookup_indicator(client, request['ip-dst'])
    if 'domain' in request:
        r['results'] += lookup_indicator(client, request['domain'])
    if 'hostname' in request:
        r['results'] += lookup_indicator(client, request['hostname'])
    if 'url' in request:
        r['results'] += lookup_indicator(client, request['url'])

    # Return any errors generated from lookup to the UI and remove duplicates

    uniq = []
    log.debug(r['results'])
    for item in r['results']:
        log.debug(item)
        if 'error' in item:
            misperrors['error'] = item['error']
            return misperrors
        if item not in uniq:
            uniq.append(item)
    r['results'] = uniq
    return r


def lookup_indicator(client, query):
    result = client.search_url(query)
    log.debug('RESULTS: ' + json.dumps(result))
    r = []
    misp_comment = "{}: Enriched via the urlscan module".format(query)

    # Determine if the page is reachable
    for request in result['data']['requests']:
        if request['response'].get('failed'):
            if request['response']['failed']['errorText']:
                log.debug('The page could not load')
                r.append(
                    {'error': 'Domain could not be resolved: {}'.format(request['response']['failed']['errorText'])})

    if result.get('page'):
        if result['page'].get('domain'):
            misp_val = result['page']['domain']
            r.append({'types': 'domain',
                      'categories': ['Network activity'],
                      'values': misp_val,
                      'comment': misp_comment})

        if result['page'].get('ip'):
            misp_val = result['page']['ip']
            r.append({'types': 'ip-dst',
                      'categories': ['Network activity'],
                      'values': misp_val,
                      'comment': misp_comment})

        if result['page'].get('country'):
            misp_val = 'country: ' + result['page']['country']
            if result['page'].get('city'):
                misp_val += ', city: ' + result['page']['city']
            r.append({'types': 'text',
                      'categories': ['External analysis'],
                      'values': misp_val,
                      'comment': misp_comment})

        if result['page'].get('asn'):
            misp_val = result['page']['asn']
            r.append({'types': 'AS', 'categories': ['External analysis'], 'values': misp_val, 'comment': misp_comment})

        if result['page'].get('asnname'):
            misp_val = result['page']['asnname']
            r.append({'types': 'text',
                      'categories': ['External analysis'],
                      'values': misp_val,
                      'comment': misp_comment})

    if result.get('stats'):
        if result['stats'].get('malicious'):
            log.debug('There is something in results > stats > malicious')
            threat_list = set()

            if 'matches' in result['meta']['processors']['gsb']['data']:
                for item in result['meta']['processors']['gsb']['data']['matches']:
                    if item['threatType']:
                        threat_list.add(item['threatType'])

            threat_list = ', '.join(threat_list)
            log.debug('threat_list values are: \'' + threat_list + '\'')

            if threat_list:
                misp_val = '{} threat(s) detected'.format(threat_list)
                r.append({'types': 'text',
                          'categories': ['External analysis'],
                          'values': misp_val,
                          'comment': misp_comment})

    if result.get('lists'):
        if result['lists'].get('urls'):
            for url in result['lists']['urls']:
                url = url.lower()
                if 'office' in url:
                    misp_val = "Possible Office-themed phishing"
                elif 'o365' in url or '0365' in url:
                    misp_val = "Possible O365-themed phishing"
                elif 'microsoft' in url:
                    misp_val = "Possible Microsoft-themed phishing"
                elif 'paypal' in url:
                    misp_val = "Possible PayPal-themed phishing"
                elif 'onedrive' in url:
                    misp_val = "Possible OneDrive-themed phishing"
                elif 'docusign' in url:
                    misp_val = "Possible DocuSign-themed phishing"
                r.append({'types': 'text',
                          'categories': ['External analysis'],
                          'values': misp_val,
                          'comment': misp_comment})

    if result.get('task'):
        if result['task'].get('reportURL'):
            misp_val = result['task']['reportURL']
            r.append({'types': 'link',
                      'categories': ['External analysis'],
                      'values': misp_val,
                      'comment': misp_comment})

        if result['task'].get('screenshotURL'):
            image_url = result['task']['screenshotURL']
            r.append({'types': 'link',
                      'categories': ['External analysis'],
                      'values': image_url,
                      'comment': misp_comment})
            # ## TO DO ###
            # ## Add ability to add an in-line screenshot of the target website into an attribute
            # screenshot = requests.get(image_url).content
            # r.append({'types': ['attachment'],
            #           'categories': ['External analysis'],
            #           'values': image_url,
            #           'image': str(base64.b64encode(screenshot), 'utf-8'),
            #           'comment': 'Screenshot of website'})

    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


class urlscanAPI():
    def __init__(self, apikey=None, uuid=None):
        self.key = apikey
        self.uuid = uuid

    def request(self, query):
        log.debug('From request function with the parameter: ' + query)
        payload = {'url': query}
        headers = {'API-Key': self.key,
                   'Content-Type': "application/json",
                   'Cache-Control': "no-cache"}

        # Troubleshooting problems with initial search request
        log.debug('PAYLOAD: ' + json.dumps(payload))
        log.debug('HEADERS: ' + json.dumps(headers))

        search_url_string = "https://urlscan.io/api/v1/scan/"
        response = requests.request("POST",
                                    search_url_string,
                                    data=json.dumps(payload),
                                    headers=headers)

        # HTTP 400 - Bad Request
        if response.status_code == 400:
            raise Exception('HTTP Error 400 - Bad Request')

        # HTTP 404 - Not found
        if response.status_code == 404:
            raise Exception('HTTP Error 404 - These are not the droids you\'re looking for')

        # Any other status code
        if response.status_code != 200:
            raise Exception('HTTP Error ' + str(response.status_code))

        if response.text:
            response = json.loads(response.content.decode("utf-8"))
            time.sleep(3)
            self.uuid = response['uuid']

            # Strings for to check for errors on the results page
            # Null response string for any unavailable resources
            null_response_string = '"status": 404'
            # Redirect string accounting for 301/302/303/307/308 status codes
            redirect_string = '"status": 30'
            # Normal response string with 200 status code
            normal_response_string = '"status": 200'

            results_url_string = "https://urlscan.io/api/v1/result/" + self.uuid
            log.debug('Results URL: ' + results_url_string)

            # Need to wait for results to process and check if they are valid
            tries = 10
            while tries >= 0:
                results = requests.request("GET", results_url_string)
                log.debug('Made a GET request')
                results = results.content.decode("utf-8")
                # checking if there is a 404 status code and no available resources
                if null_response_string in results and \
                        redirect_string not in results and \
                        normal_response_string not in results:
                    log.debug('Results not processed. Please check again later.')
                    time.sleep(3)
                    tries -= 1
                else:
                    return json.loads(results)

            raise Exception('Results contained a 404 status error and could not be processed.')

    def search_url(self, query):
        log.debug('From search_url with parameter: ' + query)
        return self.request(query)
