import json
import base64

misperrors = {'error': 'Error'}

# config fields that your code expects from the site admin
moduleconfig = {
    'foo': {
        'type': 'string',
        'description': 'blablabla',
        'value': 'xyz'
    },
    'bar': {
        'type': 'string',
        'value': 'meh'
    }
};

# blocking modules break the exection of the chain of actions (such as publishing)
blocking = False

# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules the actual boolean value determines whether we break execution
returns = 'boolean'


# the list of hook-points that it can hook
hooks = ['publish']


moduleinfo = {'version': '0.1', 'author': 'Andras Iklody',
              'description': 'This module is merely a test, always returning true. Triggers on event publishing.',
              'module-type': ['action']}


def handler(q=False):
    if q is False:
        return False
    r = True
    result = json.loads(q)  # noqa
    output = ''  # Insert your magic here!
    r = {"data": r}
    return r


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup['responseType'] = responseType
    except NameError:
        pass
    try:
        inputSource
        modulesetup['resultType'] = resultType
    except NameError:
        pass
    try:
        hooks
        modulesetup['hooks'] = hooks
    except NameError:
        pass
    try:
        hooks
        modulesetup['blocking'] = blocking
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
