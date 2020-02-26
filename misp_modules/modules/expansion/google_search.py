import json
try:
    from google import google
except ImportError:
    print("GoogleAPI not installed. Command : pip install git+https://github.com/abenassi/Google-Search-API")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url'], 'output': ['text']}
moduleinfo = {'author': 'Oun & Gindt', 'module-type': ['hover'],
              'description': 'An expansion hover module to expand google search information about an URL'}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('url'):
        return {'error': "Unsupported attributes type"}
    num_page = 1
    res = ""
    search_results = google.search(request['url'], num_page)
    for i in range(3):
        res += "("+str(i+1)+")" + '\t'
        res += json.dumps(search_results[i].description, ensure_ascii=False)
        res += '\n\n'
    return {'results': [{'types': mispattributes['output'], 'values':res}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
