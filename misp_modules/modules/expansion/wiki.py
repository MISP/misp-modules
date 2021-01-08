import json
from SPARQLWrapper import SPARQLWrapper, JSON

misperrors = {'error': 'Error'}
mispattributes = {'input': ['text'], 'output': ['text']}
moduleinfo = {'version': '0.2', 'author': 'Roman Graf', 'description': 'An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.', 'module-type': ['hover']}
moduleconfig = []
# sample query text 'Microsoft' should provide Wikidata link https://www.wikidata.org/wiki/Q2283 in response
wiki_api_url = 'https://query.wikidata.org/bigdata/namespace/wdq/sparql'


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('text'):
        misperrors['error'] = 'Query text missing'
        return misperrors

    sparql = SPARQLWrapper(wiki_api_url)
    query_string = \
        "SELECT ?item \n" \
        "WHERE { \n" \
        "?item rdfs:label\"" + request.get('text') + "\" @en \n" \
        "}\n"
    sparql.setQuery(query_string)
    sparql.setReturnFormat(JSON)
    results = sparql.query().convert()
    summary = ''
    try:
        result = results["results"]["bindings"]
        summary = result[0]["item"]["value"] if result else 'No additional data found on Wikidata'
    except Exception as e:
        misperrors['error'] = 'wikidata API not accessible {}'.format(e)
        return misperrors['error']

    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
