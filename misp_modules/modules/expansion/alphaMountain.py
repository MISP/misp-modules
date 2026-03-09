import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['ip', 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'domain', 'hostname', 'url', 'uri', 'link'],
    'output': ['text', 'comment'],
    'format': 'misp_standard',
}

userConfig = {
    "license": {
        "type": "String",
        "errorMessage": "alphaMountain license key is required",
        "message": "Your alphaMountain API license key",
        "required": True,
    },
    "scan_depth": {
        "type": "String",
        "message": "Scan depth: low, medium, or high (default: medium)",
        "default": "medium",
        "required": False,
    },
    "partner_type": {
        "type": "String",
        "message": "Partner type (default: partner.info)",
        "default": "partner.info",
        "required": False,
    },
}

moduleconfig = list(userConfig.keys())

moduleinfo = {
    'version': '1.0',
    'author': 'alphaMountain',
    'description': (
        'alphaMountain threat intelligence lookup for IPs, domains, hostnames, and URLs - adds risk score tags'
    ),
    'module-type': ['expansion', 'hover'],
    'name': 'alphaMountain_risk',
    'logo': '',
    'requirements': [],
    'features': '',
    'references': [],
}


def handler(q=False):
    """Main handler function called by MISP"""

    if q is False:
        return False

    try:
        request = json.loads(q)
    except Exception as e:
        return {'error': f'Invalid JSON input: {str(e)}'}

    if not request.get('config'):
        return {'error': 'Configuration required'}

    config = request['config']
    if 'license' not in config:
        return {'error': 'License key required in module configuration'}

    attribute = request.get('attribute')
    if not attribute:
        return {'error': 'No attribute provided'}

    # Check for required fields for MISP modules
    required_fields = ['type', 'value', 'uuid']
    if not all(field in attribute for field in required_fields):
        return {'error': f'Invalid attribute format, missing fields: {required_fields}'}

    # Validate attribute type is supported
    if attribute['type'] not in mispattributes['input']:
        return {'error': f'Unsupported attribute type: {attribute["type"]}'}

    license_key = config['license']
    api_url = 'https://api.alphamountain.ai/threat/uri'
    scan_depth = config.get('scan_depth', 'medium')
    partner_type = config.get('partner_type', 'partner.info')

    # Map MISP attribute type to alphaMountain API category and extract value
    ioc_value = get_ioc_value(attribute)

    try:
        threat_data = query_alphamountain_api(api_url, license_key, ioc_value, scan_depth, partner_type)

        if not threat_data:
            return {'error': 'No data returned from alphaMountain API'}

        # Create results dictionary - DO NOT include the original attribute
        results = {'Attribute': []}

        # Process the response and create attributes with tags
        process_threat_response(threat_data, results, attribute)

        return {'results': results}

    except requests.RequestException as e:
        return {'error': f'API request failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Processing error: {str(e)}'}


def get_ioc_value(attribute):
    """Extract IOC value from attribute, handling IPs with ports"""
    attr_type = attribute['type']
    attr_value = attribute['value']

    # For IP addresses with ports, strip the port (alphaMountain API doesn't support ports)
    if attr_type in ['ip-src|port', 'ip-dst|port']:
        return attr_value.split('|')[0]

    return attr_value


def query_alphamountain_api(api_url, license_key, ioc_value, scan_depth, partner_type):
    """Query the alphaMountain API for threat intelligence"""

    headers = {'Content-Type': 'application/json'}
    payload = {'uri': ioc_value, 'license': license_key, 'version': 1, 'type': partner_type, 'scan_depth': scan_depth}

    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

        return response.json()

    except requests.exceptions.HTTPError as e:
        status = response.status_code if response else "No status"
        body = response.text[:500] if response else "No response body"
        raise ValueError(f"HTTP {status}: {body}")

    except requests.exceptions.RequestException as e:
        raise ValueError(f"Request failed: {str(e)}")

    except Exception as e:
        raise ValueError(f"Unexpected error: {str(e)}")


def process_threat_response(threat_data, results, original_attribute):
    """Process the API response and apply risk score tag to the original attribute"""

    # Create tags list - only risk score
    tags = []

    if not isinstance(threat_data, dict):
        # Add error tag
        tags.append({'name': 'alphaMountain:error', 'colour': '#ff0000'})
    else:
        status = threat_data.get('status', {})
        if status.get('threat') != 'Success':
            tags.append({'name': 'alphaMountain:api-error', 'colour': '#ff0000'})
        else:
            threat_info = threat_data.get('threat', {})

            if isinstance(threat_info, dict) and threat_info:
                score = threat_info.get('score', 'N/A')

                # Add risk score tag
                if score != 'N/A':
                    try:
                        score_float = round(float(score), 2)
                        risk_level = get_risk_level(score_float)
                        risk_color = get_risk_color(risk_level)

                        # Add specific score tag with full precision
                        tags.append({'name': f'alphaMountain:risk-score="{score_float}"', 'colour': risk_color})

                    except (ValueError, TypeError):
                        # If score is not a valid number, add a generic tag
                        tags.append({'name': 'alphaMountain:risk-score="unknown"', 'colour': '#ffa500'})

    # If no tags were added, add a no-data tag
    if not tags:
        tags.append({'name': 'alphaMountain:no-data', 'colour': '#ffa500'})

    # Create enriched attribute with only risk score tag
    enriched_attribute = {
        'type': original_attribute['type'],
        'value': original_attribute['value'],
        'category': original_attribute.get('category', 'Network activity'),
        'to_ids': original_attribute.get('to_ids', False),
        'disable_correlation': original_attribute.get('disable_correlation', False),
        'comment': 'alphaMountain threat intelligence analysis',
        'Tag': tags,
    }

    results['Attribute'].append(enriched_attribute)


def get_risk_level(score):
    """Determine risk level based on score"""
    int_score = int(score)
    if int_score >= 8:
        return 'high'
    elif int_score >= 7:
        return 'medium'
    elif int_score >= 6:
        return 'low'
    else:
        return 'minimal'


def get_risk_color(risk_level):
    """Get color code for risk level"""
    color_map = {
        'high': '#ff0000',  # Red
        'medium': '#ffa500',  # Orange
        'low': '#ffff00',  # Yellow
        'minimal': '#00cc00',  # Green
    }
    return color_map.get(risk_level, '#cccccc')


def introspection():
    """Return module metadata for MISP"""
    modulesetup = {}
    modulesetup['userConfig'] = userConfig
    modulesetup['input'] = mispattributes['input']
    modulesetup['output'] = mispattributes['output']
    modulesetup['format'] = 'misp_standard'
    return modulesetup


def version():
    """Return module version"""
    moduleinfo['config'] = moduleconfig
    return moduleinfo
