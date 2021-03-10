import json
import random
import time
try:
    from googleapi import google
except ImportError:
    print("GoogleAPI not installed. Command : pip install git+https://github.com/abenassi/Google-Search-API")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url'], 'output': ['text']}
moduleinfo = {'author': 'Oun & Gindt', 'module-type': ['hover'],
              'description': 'An expansion hover module to expand google search information about an URL'}

def sleep(retry):
    time.sleep(random.uniform(0, min(40, 0.01 * 2 ** retry)))

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('url'):
        return {'error': "Unsupported attributes type"}
    num_page = 1
    res = ""
    # The googleapi module sets a random useragent. The output depends on the useragent.
    # It's better to retry 3 times.
    for retry in range(3):
        search_results = google.search(request['url'], num_page)
        if len(search_results) > 0:
            break
        sleep(retry)
    for i, search_result in enumerate(search_results):
        res += "("+str(i+1)+")" + '\t'
        res += json.dumps(search_result.description, ensure_ascii=False)
        res += '\n\n'
    return {'results': [{'types': mispattributes['output'], 'values':res}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
