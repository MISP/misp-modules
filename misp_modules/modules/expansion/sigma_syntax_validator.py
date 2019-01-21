import json
try:
    import yaml
    from sigma.parser.rule import SigmaParser
    from sigma.configuration import SigmaConfiguration
except ImportError:
    print("sigma or yaml is missing, use 'pip3 install sigmatools' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['sigma'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer', 'module-type': ['expansion', 'hover'],
              'description': 'An expansion hover module to perform a syntax check on sigma rules'}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('sigma'):
        misperrors['error'] = 'Sigma rule missing'
        return misperrors
    config = SigmaConfiguration()
    try:
        parser = SigmaParser(yaml.safe_load(request.get('sigma')), config)
        result = ("Syntax valid: {}".format(parser.values))
    except Exception as e:
        result = ("Syntax error: {}".format(str(e)))
    return {'results': [{'types': mispattributes['output'], 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
