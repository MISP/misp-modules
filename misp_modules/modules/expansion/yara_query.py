import json
import sys

misperrors = {'error': 'Error'}
moduleinfo = {'version': '1', 'author': 'Christian STUDER',
              'description': 'Yara export for hashes.',
              'module-type': ['expansion', 'hover'],
              'require_standard_format': True}
moduleconfig = []
mispattributes = {'input': ['md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256'], 'output': ['yara rule']}

def hash_cond(hashtype, hashvalue):
    condition = 'hash.{}(0, filesize) == {}'.format(hashtype, hashvalue.lower())
    return condition, 'hash'

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    del request['module']
    if 'event_id' in request:
        del request['event_id']
    uuid = request.pop('attribute_uuid') if 'attribute_uuid' in request else None
    rules = []
    types = []
    for attribute_type, value in request.items():
        if 'filename' in attribute_type:
            _, attribute_type = attribute_type.split('|')
            _, value = value.split('|')
        condition, required_module = hash_cond(attribute_type, value)
        condition = '\r\n\t\t'.join([condition])
        import_section = '\r\n'.join(['import "{}"'.format(required_module)])
        rule_start = 'rule %s {' % uuid if uuid else 'rule {'
        condition = '\tcondition:\r\n\t\t{}'.format(condition)
        rules.append('\r\n'.join([rule_start, condition, '}']))
        types.append('yara')
    return {'results': [{'types': [t], 'values': [v]} for t, v in zip(types, rules)]}

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
