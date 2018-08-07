import json
import requests
try:
    import yara
except ModuleNotFoundError:
    print("yara is missing, use 'pip3 install yara' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['yara'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Dennis Rand', 'description': 'An expansion hover module to perform a syntax check on if yara rules are valid or not.', 'module-type': ['hover']}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('yara'):
        misperrors['error'] = 'Yara rule missing'
        return misperrors

    try:
        rules = yara.compile(source=request.get('yara'))
        summary = ("Syntax valid")
    except Exception as e:
        summary = ("Syntax error: " + str(e))

    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
