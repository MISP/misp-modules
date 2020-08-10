import requests
import json

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-dst', 'ip-src'], 'output': ['text']}
moduleinfo = {
    'version': '0.2',
    'author': 'Aurélien Schwab <aurelien.schwab+dev@gmail.com>',
    'description': 'Module to access GreyNoise.io API.',
    'module-type': ['hover']
}
moduleconfig = ['api_key']

greynoise_api_url = 'https://api.greynoise.io/v2/noise/quick/'
codes_mapping = {
    '0x00': 'The IP has never been observed scanning the Internet',
    '0x01': 'The IP has been observed by the GreyNoise sensor network',
    '0x02': 'The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed',
    '0x03': 'The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network',
    '0x04': 'Reserved',
    '0x05': 'This IP is commonly spoofed in Internet-scan activity',
    '0x06': 'This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently',
    '0x07': 'This IP is invalid',
    '0x08': 'This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 60 days'
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('api_key'):
        return {'error': 'Missing Greynoise API key.'}
    headers = {
        'Accept': 'application/json',
        'key': request['config']['api_key']
    }
    for input_type in mispattributes['input']:
        if input_type in request:
            ip = request[input_type]
            break
    else:
        misperrors['error'] = "Unsupported attributes type."
        return misperrors
    response = requests.get(f'{greynoise_api_url}{ip}', headers=headers)  # Real request
    if response.status_code == 200:  # OK (record found)
        return {'results': [{'types': mispattributes['output'], 'values': codes_mapping[response.json()['code']]}]}
    # There is an error
    errors = {
        400: "Bad request.",
        401: "Unauthorized. Please check your API key.",
        429: "Too many requests. You've hit the rate-limit."
    }
    try:
        misperrors['error'] = errors[response.status_code]
    except KeyError:
        misperrors['error'] = f'GreyNoise API not accessible (HTTP {response.status_code})'
    return misperrors['error']


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
