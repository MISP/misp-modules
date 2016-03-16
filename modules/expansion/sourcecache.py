import json
from url_archiver import url_archiver

misperrors = {'error': 'Error'}
mispattributes = {'input': ['link'], 'output': ['link']}
moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy', 'description': 'Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.'}
moduleconfig = ['archivepath']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if (request.get('config')):
        archive_path = request['config']['archivepath']
    else:
        archive_path = '/tmp/'
    if request.get('link'):
        tocache = request['link']
        archiver = url_archiver.Archive(archive_path=archive_path)
        archiver.fetch(url=tocache)
        mispattributes['output'] = ['link']
    else:
        misperrors['error'] = "Link is missing"
        return misperrors
    r = {'results': [{'types': mispattributes['output'], 'values': tocache}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
