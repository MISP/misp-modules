import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {
        'input': ['url'],
        'output': ['text']
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Evert Kors',
              'description': 'MODULE_DESCRIPTION',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['cuckoo_api']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get('config')
    if config is None:
        misperrors['error'] = 'config is missing'
        return misperrors

    cuck = config.get('cuckoo_api')
    if cuck is None:
        misperrors['error'] = 'cuckoo api url is missing'
        return misperrors

    # The url to submit
    url = request.get('url')

    HEADERS = {"Authorization": "Bearer S4MPL3"}

    urls = [
        url
    ]

    try:
        r = requests.post(
            "%s/tasks/create/submit" % (cuck),
            headers=HEADERS,
            data={"strings": "\n".join(urls)}
        )
    except Exception as e:
        misperrors['error'] = str(e)
        return misperrors

    r = {'results': [{'types': "text", 'values': "cool"}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
