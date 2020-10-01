import json
from socialscan.platforms import Platforms
from socialscan.util import sync_execute_queries

moduleinfo = {
    'version': '1',
    'author': 'Christian Studer',
    'description': 'Module to query several online platforms to look for existing accounts.',
    'module-type': ['hover']
}
mispattributes = {
    'input': [
        'github-username',
        'target-user',
        'email',
        'email-src',
        'email-dst',
        'target-email',
        'whois-registrant-email'
    ],
    'output': ['text']
}
moduleconfig = []

_PLATFORMS = [
    Platforms.INSTAGRAM,
    Platforms.TWITTER,
    Platforms.GITHUB,
    Platforms.TUMBLR,
    Platforms.LASTFM
]
_EMAIL_PLATFORMS = [
    Platforms.PINTEREST,
    Platforms.SPOTIFY,
    Platforms.FIREFOX
]
_EMAIL_PLATFORMS.extend(_PLATFORMS)
_USERNAME_PLATFORMS = [
    Platforms.SNAPCHAT,
    Platforms.GITLAB,
    Platforms.REDDIT,
    Platforms.YAHOO
]
_USERNAME_PLATFORMS.extend(_PLATFORMS)


def parse_results(query_results, feature):
    results = []
    for result in query_results:
        if not result.success:
            results.append(f'Unable to retrieve the {feature} on {result.platform}.')
            continue
        if not result.valid:
            results.append(f'Invalid response from {result.platform}.')
            continue
        statement = 'No account' if result.available else 'There is an account'
        results.append(f'{statement} linked to the {feature} on {result.platform}.')
    to_return = [
        {
            'types': mispattributes['output'],
            'values': result
        } for result in results
    ]
    return {'results': to_return}


def parse_email(email):
    results = sync_execute_queries([email], platforms=_EMAIL_PLATFORMS)
    return parse_results(results, 'email address')


def parse_username(username, platforms=_USERNAME_PLATFORMS):
    results = sync_execute_queries([username], platforms=platforms)
    return parse_results(results, 'username')


def parse_github_username(username):
    return parse_username(username, platforms=[Platforms.GITHUB])


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('github-username'):
        return parse_github_username(request['github-username'])
    if request.get('target-user'):
        return parse_username(request['target-user'])
    for attribute_type in mispattributes['input'][2:]:
        if request.get(attribute_type):
            return parse_email(request[attribute_type])
    return {'error': 'Unsupported attributes type'}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
