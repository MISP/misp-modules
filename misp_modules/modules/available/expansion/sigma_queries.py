import io
import json
try:
    from sigma.parser.collection import SigmaCollectionParser
    from sigma.configuration import SigmaConfiguration
    from sigma.backends.discovery import getBackend
except ImportError:
    print("sigma or yaml is missing, use 'pip3 install sigmatools' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['sigma'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer', 'module-type': ['expansion', 'hover'],
              'description': 'An expansion hover module to display the result of sigma queries.'}
moduleconfig = []
sigma_targets = ('es-dsl', 'es-qs', 'graylog', 'kibana', 'xpack-watcher', 'logpoint', 'splunk', 'grep', 'wdatp', 'splunkxml', 'arcsight', 'qualys')


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('sigma'):
        misperrors['error'] = 'Sigma rule missing'
        return misperrors
    config = SigmaConfiguration()
    f = io.TextIOWrapper(io.BytesIO(request.get('sigma').encode()), encoding='utf-8')
    parser = SigmaCollectionParser(f, config)
    targets = []
    results = []
    for t in sigma_targets:
        backend = getBackend(t)(config, {'rulecomment': False})
        try:
            parser.generate(backend)
            result = backend.finalize()
            if result:
                results.append(result)
                targets.append(t)
        except Exception:
            continue
    d_result = {t: r.strip() for t, r in zip(targets, results)}
    return {'results': [{'types': mispattributes['output'], 'values': d_result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
