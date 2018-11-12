import json
import re
try:
    import yara
except (OSError, ImportError):
    print("yara is missing, use 'pip3 install -I -r REQUIREMENTS' from the root of this repository to install it.")

misperrors = {'error': 'Error'}
moduleinfo = {'version': '1', 'author': 'Christian STUDER',
              'description': 'Yara export for hashes.',
              'module-type': ['expansion', 'hover'],
              'require_standard_format': True}
moduleconfig = []
mispattributes = {'input': ['md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256'], 'output': ['yara']}

def get_hash_condition(hashtype, hashvalue):
    condition = 'hash.{}(0, filesize) == "{}"'.format(hashtype, hashvalue.lower())
    return condition, 'hash'

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    del request['module']
    if 'event_id' in request:
        del request['event_id']
    uuid = request.pop('attribute_uuid') if 'attribute_uuid' in request else None
    attribute_type, value = list(request.items())[0]
    if 'filename' in attribute_type:
        _, attribute_type = attribute_type.split('|')
        _, value = value.split('|')
    condition, required_module = get_hash_condition(attribute_type, value)
    import_section = 'import "{}"'.format(required_module)
    rule_start = 'import "hash" \r\nrule %s_%s {' % (attribute_type.upper(), re.sub(r'\W+', '_', uuid)) if uuid else 'import "hash"\r\nrule %s {' % attribute_type.upper()
    condition = '\tcondition:\r\n\t\t{}'.format(condition)
    rule = '\r\n'.join([rule_start, condition, '}'])
    try:
        yara.compile(source=rule)
    except Exception as e:
        misperrors['error'] = 'Syntax error: {}'.format(e)
        return misperrors
    return {'results': [{'types': mispattributes['output'], 'values': rule}]}

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
