"""
Flowtriq DDoS Intelligence Module for MISP

Enriches IP addresses with DDoS attack data from Flowtriq.
When given an IP, queries the Flowtriq API to check if this IP
has been observed as a DDoS attack source across Flowtriq's
network of monitored infrastructure.

Returns attack context including attack families, severity,
peak traffic rates, geographic origin, and threat intel matches.
"""

import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['ip-src', 'ip-dst'],
    'format': 'misp_standard',
}
moduleinfo = {
    'version': '1.0',
    'author': 'Flowtriq',
    'description': 'Query Flowtriq for DDoS attack intelligence on IP addresses',
    'module-type': ['expansion', 'hover'],
    'name': 'Flowtriq DDoS Intelligence',
    'logo': 'flowtriq.png',
    'requirements': ['Flowtriq API key and API URL'],
    'features': (
        'Queries the Flowtriq IP threat lookup API to check whether an IP '
        'has been observed as a DDoS attack source. Returns structured '
        'enrichment data including attack families, severity breakdown, '
        'peak PPS, ASN, country, risk score, and related attacker IPs.'
    ),
    'references': ['https://flowtriq.com'],
    'input': 'An IP address attribute (ip-src or ip-dst).',
    'output': (
        'MISP attributes and objects describing DDoS attack activity '
        'associated with the queried IP: attack types, timestamps, '
        'severity, peak traffic, related IPs, and threat intel matches.'
    ),
}
moduleconfig = ['api_key', 'api_url']

_DEFAULT_API_URL = 'https://flowtriq.com'
_TIMEOUT = 15


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    # Validate config
    config = request.get('config', {})
    api_key = config.get('api_key', '').strip()
    api_url = config.get('api_url', '').strip().rstrip('/') or _DEFAULT_API_URL

    if not api_key:
        misperrors['error'] = 'Flowtriq API key is required. Set it in the module configuration.'
        return misperrors

    # Extract IP from the request
    ip = None
    attribute = request.get('attribute', {})
    for attr_type in ('ip-src', 'ip-dst'):
        if attr_type in request:
            ip = request[attr_type]
            break
    if not ip and attribute.get('value'):
        ip = attribute['value']

    if not ip:
        misperrors['error'] = 'No IP address provided in the request.'
        return misperrors

    # Query Flowtriq IP threat lookup
    try:
        response = requests.post(
            f'{api_url}/api/ip-lookup.php',
            json={'ip': ip},
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'MISP-Flowtriq/1.0',
            },
            timeout=_TIMEOUT,
            verify=True,
        )
    except requests.exceptions.ConnectionError:
        misperrors['error'] = f'Cannot connect to Flowtriq API at {api_url}'
        return misperrors
    except requests.exceptions.Timeout:
        misperrors['error'] = f'Flowtriq API request timed out after {_TIMEOUT}s'
        return misperrors
    except requests.exceptions.RequestException as e:
        misperrors['error'] = f'Flowtriq API request failed: {e}'
        return misperrors

    if response.status_code != 200:
        misperrors['error'] = f'Flowtriq API returned HTTP {response.status_code}'
        return misperrors

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        misperrors['error'] = 'Flowtriq API returned invalid JSON'
        return misperrors

    if not data.get('ok'):
        misperrors['error'] = data.get('error', 'Flowtriq API returned an error')
        return misperrors

    if not data.get('found'):
        return {'results': []}

    # Build enrichment results
    results = _build_results(ip, data, attribute)
    return {'results': results}


def _build_results(ip, data, attribute):
    """Build MISP-standard enrichment results from Flowtriq API response."""
    results = []

    risk_score = data.get('risk_score', 0)
    reputation = data.get('reputation')
    incidents = data.get('incidents', {})
    threat_intel = data.get('threat_intel', [])
    related_ips = data.get('related_ips', {})
    ioc_matches = data.get('ioc_matches', {})

    # -- Summary comment on the original attribute --
    summary_parts = []
    summary_parts.append(f'Flowtriq risk score: {risk_score}/100')

    total_incidents = incidents.get('total', 0)
    if total_incidents:
        summary_parts.append(f'Seen in {total_incidents} DDoS incident(s)')

    if reputation:
        attack_count = reputation.get('attack_count', 0)
        tenants_seen = reputation.get('tenants_seen', 0)
        if attack_count:
            summary_parts.append(f'{attack_count} attacks across {tenants_seen} network(s)')
        if reputation.get('top_attack_family'):
            summary_parts.append(f'Primary vector: {reputation["top_attack_family"]}')
        if reputation.get('country'):
            summary_parts.append(f'Country: {reputation["country"]}')
        if reputation.get('asn'):
            summary_parts.append(f'ASN: {reputation["asn"]}')
        if reputation.get('peak_pps'):
            summary_parts.append(f'Peak PPS: {reputation["peak_pps"]:,}')

    families = incidents.get('attack_families', {})
    if families:
        top_families = ', '.join(list(families.keys())[:5])
        summary_parts.append(f'Attack families: {top_families}')

    severity = incidents.get('severity', {})
    sev_parts = []
    for level in ('critical', 'high', 'medium', 'low'):
        count = severity.get(level, 0)
        if count:
            sev_parts.append(f'{count} {level}')
    if sev_parts:
        summary_parts.append(f'Severity: {", ".join(sev_parts)}')

    if threat_intel:
        sources = set()
        for ti in threat_intel:
            sources.add(ti.get('source', 'unknown'))
        summary_parts.append(f'Threat intel sources: {", ".join(sorted(sources))}')

    if ioc_matches:
        summary_parts.append(f'IOC matches: {", ".join(list(ioc_matches.keys())[:5])}')

    summary_text = '. '.join(summary_parts) + '.'

    results.append({
        'types': ['text'],
        'categories': ['External analysis'],
        'values': [summary_text],
        'comment': f'Flowtriq DDoS intelligence for {ip}',
    })

    # -- Reputation text attribute --
    if reputation:
        rep_lines = [f'Flowtriq IP Reputation for {ip}:']
        rep_lines.append(f'  Risk Score: {risk_score}/100')
        rep_lines.append(f'  Attack Count: {reputation.get("attack_count", 0)}')
        rep_lines.append(f'  Networks Seen: {reputation.get("tenants_seen", 0)}')
        rep_lines.append(f'  First Seen: {reputation.get("first_seen", "N/A")}')
        rep_lines.append(f'  Last Seen: {reputation.get("last_seen", "N/A")}')
        rep_lines.append(f'  Top Attack Family: {reputation.get("top_attack_family", "N/A")}')
        rep_lines.append(f'  Top Protocol: {reputation.get("top_protocol", "N/A")}')
        rep_lines.append(f'  Country: {reputation.get("country", "N/A")}')
        rep_lines.append(f'  ASN: {reputation.get("asn", "N/A")}')
        rep_lines.append(f'  Peak PPS: {reputation.get("peak_pps", 0):,}')
        tags = reputation.get('tags', [])
        if tags:
            rep_lines.append(f'  Tags: {", ".join(tags)}')

        results.append({
            'types': ['text'],
            'categories': ['External analysis'],
            'values': ['\n'.join(rep_lines)],
            'comment': 'Flowtriq reputation data',
        })

    # -- ASN attribute --
    if reputation and reputation.get('asn'):
        results.append({
            'types': ['AS'],
            'categories': ['Network activity'],
            'values': [str(reputation['asn'])],
            'comment': f'ASN of {ip} per Flowtriq',
        })

    # -- First/last seen timestamps --
    if reputation:
        if reputation.get('first_seen'):
            results.append({
                'types': ['datetime'],
                'categories': ['Network activity'],
                'values': [reputation['first_seen']],
                'comment': f'Flowtriq first seen {ip}',
            })
        if reputation.get('last_seen'):
            results.append({
                'types': ['datetime'],
                'categories': ['Network activity'],
                'values': [reputation['last_seen']],
                'comment': f'Flowtriq last seen {ip}',
            })

    # -- Incident records as text --
    records = incidents.get('records', [])
    if records:
        inc_lines = [f'Flowtriq DDoS Incidents involving {ip} (last 90 days):']
        for i, rec in enumerate(records[:10], 1):
            inc_lines.append(f'  [{i}] {rec.get("date", "?")} - {rec.get("attack_family", "?")} '
                             f'({rec.get("severity", "?")}) - '
                             f'Peak: {rec.get("peak_pps", 0):,} pps / '
                             f'{rec.get("peak_bps", 0):,} bps - '
                             f'Duration: {rec.get("duration_sec", 0)}s - '
                             f'{rec.get("source_ip_count", 0)} source IPs')
            if rec.get('spoofing'):
                inc_lines.append('         Spoofing detected')
            if rec.get('botnet'):
                inc_lines.append('         Botnet indicators')

        results.append({
            'types': ['text'],
            'categories': ['External analysis'],
            'values': ['\n'.join(inc_lines)],
            'comment': 'Flowtriq incident history',
        })

    # -- Related attacker IPs --
    if related_ips:
        for related_ip, co_occurrence in list(related_ips.items())[:10]:
            results.append({
                'types': ['ip-src'],
                'categories': ['Network activity'],
                'values': [related_ip],
                'comment': f'Co-attacker with {ip} in {co_occurrence} Flowtriq incident(s)',
                'tags': ['flowtriq:related-attacker'],
            })

    # -- Threat intel feed matches --
    if threat_intel:
        ti_lines = [f'Threat Intel Matches for {ip}:']
        for ti in threat_intel:
            ti_lines.append(
                f'  - {ti.get("source", "?")} ({ti.get("threat_type", "?")}) '
                f'confidence={ti.get("confidence", "?")} '
                f'seen={ti.get("times_seen", "?")}x '
                f'[{ti.get("first_seen", "?")} to {ti.get("last_seen", "?")}]'
            )
            if ti.get('description'):
                ti_lines.append(f'    {ti["description"]}')

        results.append({
            'types': ['text'],
            'categories': ['External analysis'],
            'values': ['\n'.join(ti_lines)],
            'comment': 'Flowtriq threat intel feed matches',
        })

    return results


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
