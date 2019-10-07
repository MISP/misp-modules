import json
try:
    from stix2patterns.validator import run_validator
except ImportError:
    print("stix2 patterns python library is missing, use 'pip3 install stix2-patterns' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['stix2-pattern'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer', 'module-type': ['hover'],
              'description': 'An expansion hover module to perform a syntax check on stix2 patterns.'}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('stix2-pattern'):
        misperrors['error'] = 'STIX2 pattern missing'
        return misperrors
    pattern = request.get('stix2-pattern')
    syntax_errors = []
    for p in pattern[1:-1].split(' AND '):
        syntax_validator = run_validator("[{}]".format(p))
        if syntax_validator:
            for error in syntax_validator:
                syntax_errors.append(error)
    if syntax_errors:
        s = 's' if len(syntax_errors) > 1 else ''
        s_errors = ""
        for error in syntax_errors:
            s_errors += "{}\n".format(error[6:])
        result = "Syntax error{}: \n{}".format(s, s_errors[:-1])
    else:
        result = "Syntax valid"
    return {'results': [{'types': mispattributes['output'], 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
