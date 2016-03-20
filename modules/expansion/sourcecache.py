import json
from url_archiver import url_archiver

misperrors = {'error': 'Error'}
mispattributes = {'input': ['link', 'url'], 'output': ['attachment', 'malware-sample']}
moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy', 'description': 'Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.', 'module-type': ['expansion']}
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
        data = __archiveLink(archive_path, tocache)
        mispattributes['output'] = ['attachment']
    elif request.get('url'):
        tocache = request['url']
        data = __archiveLink(archive_path, tocache)
        mispattributes['output'] = ['malware-sample']
    else:
        misperrors['error'] = "Link is missing"
        return misperrors
    enc_data = str(data)
    r = {'results': [{'types': mispattributes['output'], 'values': tocache, 'data': enc_data}]}
    return r


def __archiveLink(archive_path, tocache):
    archiver = url_archiver.Archive(archive_path=archive_path)
    return archiver.fetch(url=tocache, armor=True)

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
