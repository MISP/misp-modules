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
mispattributes = {'input': ['md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256', 'imphash'], 'output': ['yara']}


def extract_input_attribute(request):
    for input_type in mispattributes['input']:
        if input_type in request:
            return input_type, request[input_type]


def get_hash_condition(hashtype, hashvalue):
    hashvalue = hashvalue.lower()
    required_module, params = ('pe', '()') if hashtype == 'imphash' else ('hash', '(0, filesize)')
    return '{}.{}{} == "{}"'.format(required_module, hashtype, params, hashvalue), required_module


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = extract_input_attribute(request)
    if attribute is None:
        return {'error': f'Wrong input type, please choose in the following: {", ".join(mispattributes["input"])}'}
    uuid = request.pop('attribute_uuid') if 'attribute_uuid' in request else None
    attribute_type, value = attribute
    if 'filename' in attribute_type:
        _, attribute_type = attribute_type.split('|')
        _, value = value.split('|')
    condition, required_module = get_hash_condition(attribute_type, value)
    import_section = 'import "{}"'.format(required_module)
    rule_start = '%s\r\nrule %s_%s {' % (import_section, attribute_type.upper(), re.sub(r'\W+', '_', uuid)) if uuid else '%s\r\nrule %s {' % (import_section, attribute_type.upper())
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
