# GNU AFFERO GENERAL PUBLIC LICENSE
# Version 3, 19 November 2007
#
# ReversingLabs MISP Enrichment Module
# Version: 1.0.0
# Copyright (c) 2025 ReversingLabs. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-or-later
# This compiled module is licensed under the GNU Affero General Public License v3 (AGPL-3.0)
# See the accompanying LICENSE file in the package for full terms.
#
# Repository: https://github.com/reversinglabs/reversinglabs-misp
# Support: support@reversinglabs.com
#
# ruff: noqa: E501, E402, I001
# flake8: noqa: E501, E402

MAPPING_RULES = {
  "create": {
    "file": {
      "obj:fetch": [
        "/api/samples/v2/list/details/",
        "/api/samples/v3/{hash}/classification/"
      ],
      "file-object": {
        "obj:type": "file",
        "obj:comment": "ReversingLabs Enriched File IOC Object - {{#ref sample_summary.sha1 | sample_summary.sha256 | sample_summary.md5}}",
        "!sha1": "{{#ref sample_summary.sha1 (sha1)}} {{#Comment SHA1 hash of the analyzed file}}",
        "!md5": "{{#ref sample_summary.md5 (md5)}} {{#Comment MD5 hash of the analyzed file}}",
        "!sha256": "{{#ref sample_summary.sha256 (sha256)}} {{#Comment SHA256 hash (primary identifier)}}",
        "!sha512": "{{#ref sample_summary.sha512 (sha512)}} {{#Comment SHA512 hash if available}}",
        "!ssdeep": "{{#ref sample_summary.ssdeep (ssdeep)}} {{#Comment Fuzzy hash for similarity matching}}",
        "!imphash": "{{#ref sample_summary.imphash (imphash)}} {{#Comment PE import hash for malware family clustering}}",
        "!tlsh": "{{#ref sample_summary.tlsh (tlsh)}} {{#Comment Trend locality-sensitive hash}}",
        "size-in-bytes": "{{#ref sample_summary.file_size (size-in-bytes)}} {{#Comment File size in bytes}}",
        "text#0": "{{#ref sample_summary.file_type}} {{#Comment File type from ReversingLabs}}",
        "text#1": "{{#ref sample_summary.classification}} {{#Comment Threat classification}}",
        "text#2": "{{#ref sample_summary.riskscore}} {{#Comment Risk score (0-10)}}",
        "text#3": "{{#ref sample_summary.modified_time}} {{#Comment Last modification timestamp}}",
        "text#4": "{{#ref sample_summary.classification_result}} {{#Comment Result of classification}}",
        "entropy": "{{#ref sample_summary.entropy}} {{#Comment File entropy value}}",
        "rl:extracted_file_count": "{{#ref sample_summary.extracted_file_count}} {{#Comment Number of files extracted from this sample}}",
        "rl:classification": "{{#ref sample_summary.classification}} {{#Comment Threat classification}}",
        "rl:riskscore": "{{#ref sample_summary.riskscore}} {{#Comment Risk score (0-10)}}",
        "rl:threat_level": "{{#ref sample_summary.threat_level}} {{#Comment Threat level category}}",
        "rl:trust_factor": "{{#ref sample_summary.trust_factor}} {{#Comment Trust factor score}}",
        "rl:classification_result": "{{#ref sample_summary.classification_result}} {{#Comment Result of classification}}",
        "rl:classification_source": "{{#ref sample_summary.classification_source}} {{#Comment Source of classification}}",
        "rl:data_source": "{{#ref data_source | sample_summary.data_source | 'LOCAL'}}",
        "rl:classification_reason": "{{#ref sample_summary.classification_reason}} {{#Comment Reason for classification}}",
        "rl:file_type": "{{#ref sample_summary.file_type}}",
        "obj:analysed-with->": [
          "file-analysis"
        ],
        "file-analysis": {
          "obj:type": "report",
          "obj:comment": "ReversingLabs File Report - {{#ref sample_summary.sha1 | sample_summary.sha256 | sample_summary.md5}}",
          "link": "{{#build_link file (link)}} {{#Comment Link to ReversingLabs analysis portal}}",
          "title": "ReversingLabs File Analysis",
          "type": "threat-intelligence",
          "summary": "{{#summary}} {{#Comment Unified summary for all IOC types}}",
          "rl:classification": "{{#ref sample_summary.classification}} {{#Comment Threat classification}}",
          "rl:classification_source": "{{#ref sample_summary.classification_source}} {{#Comment Source of classification}}",
          "rl:classification_result": "{{#ref sample_summary.classification_result}} {{#Comment Result of classification}}",
          "rl:classification_reason": "{{#ref sample_summary.classification_reason}} {{#Comment Reason for classification}}"
        }
      }
    },
    "domain": {
      "obj:fetch": [
        "/api/network-threat-intel/domain/{domain}/"
      ],
      "domain-object": {
        "obj:type": "domain-ip",
        "obj:comment": "ReversingLabs Enriched Domain IOC Object - {{#ref requested_domain}}",
        "domain": "{{#ref requested_domain (domain)}} {{#Comment The queried domain name}}",
        "first-seen": "{{#ref first_seen}} {{#Comment First observation timestamp}}",
        "last-seen": "{{#ref last_seen}} {{#Comment Most recent observation timestamp}}",
        "text#0": "{{#foreach top_threats}}{{#ref threat_name}}, {{/foreach}} {{#Comment List of associated threat names}}",
        "rl:classification": "{{#ref classification}} {{#Comment Threat classification}}",
        "rl:riskscore": "{{#ref riskscore}} {{#Comment Risk score (0-10)}}",
        "rl:threat[]": "{{#foreach top_threats}}{{#ref threat_name}}{{/foreach}} {{#Comment Tags for each threat name}}",
        "rl:malware-family[]": "{{#foreach top_threats}}{{#ref threat_family}}{{/foreach}} {{#Comment Tags for each threat family}}",
        "obj:analysed-with->": [
          "domain-analysis"
        ],
        "domain-analysis": {
          "obj:type": "report",
          "obj:comment": "ReversingLabs Domain Report - {{#ref requested_domain}}",
          "title": "ReversingLabs Domain Report",
          "type": "threat-intelligence",
          "summary": "{{#summary}} {{#Comment Unified summary for all IOC types}}",
          "link": "{{#build_link domain (link)}} {{#Comment Link to ReversingLabs domain report}}",
          "obj:related-to->": [
            "dns-record"
          ],
          "dns-record": {
            "obj:type": "dns-record",
            "obj:comment": "DNS resolution records for the domain",
            "queried-domain": "{{#ref requested_domain (domain)}} {{#Comment The domain that was queried}}",
            "!a-record": "{{#dns_records A last_dns_records (ip-dst)}} {{#Comment IPv4 address records}}",
            "aaaa-record": "{{#dns_records AAAA last_dns_records (ip-dst)}} {{#Comment IPv6 address records}}",
            "cname-record": "{{#dns_records CNAME last_dns_records (domain)}} {{#Comment Canonical name records}}",
            "mx-record": "{{#dns_records MX last_dns_records (domain)}} {{#Comment Mail exchanger records}}",
            "ns-record": "{{#dns_records NS last_dns_records (domain)}} {{#Comment Name server records}}",
            "txt-record": "{{#dns_records TXT last_dns_records (text)}} {{#Comment Text records including SPF}}",
            "soa-record": "{{#dns_records SOA last_dns_records (domain)}} {{#Comment Start of authority record}}",
            "srv-record": "{{#dns_records SRV last_dns_records (domain)}} {{#Comment Service location records}}",
            "ptr-record": "{{#dns_records PTR last_dns_records (domain)}} {{#Comment Pointer records}}",
            "dns-ips[10]": {
              "obj:type": "ip-port",
              "obj:path": "last_dns_records[type=A,AAAA]",
              "obj:comment": "IP address from DNS A/AAAA record",
              "ip": "{{#ref value (ip-dst)}}"
            },
            "dns-hostnames[10]": {
              "obj:type": "domain-ip",
              "obj:path": "last_dns_records[type=NS,CNAME,MX,PTR]",
              "obj:comment": "Domain from DNS record",
              "hostname": "{{#ref value (hostname)}}"
            }
          }
        }
      }
    },
    "ip": {
      "obj:fetch": [
        "/api/network-threat-intel/ip/{ip}/report/"
      ],
      "ip-object": {
        "obj:type": "ip-port",
        "obj:comment": "ReversingLabs Enriched IP IOC Object - {{#ref requested_ip}}",
        "ip": "{{#ref requested_ip (ip-dst)}} {{#Comment The queried IP address}}",
        "text#0": "{{#ref modified_time}} {{#Comment Last modification timestamp}}",
        "text#1": "{{#ref top_threats[0].risk_score}} {{#Comment Risk score (0-10)}}",
        "rl:riskscore[]": "{{#foreach top_threats}}{{#ref risk_score}}{{/foreach}} {{#Comment Risk score tags}}",
        "rl:threat[]": "{{#foreach top_threats}}{{#ref threat_name}}{{/foreach}} {{#Comment Threat Name tags}}",
        "obj:analysed-with->": [
          "ip-analysis"
        ],
        "ip-analysis": {
          "obj:type": "report",
          "obj:comment": "ReversingLabs IP Report - {{#ref requested_ip}}",
          "title": "ReversingLabs IP Report",
          "type": "threat-intelligence",
          "summary": "{{#summary}} {{#Comment Unified summary for all IOC types}}",
          "link": "{{#build_link ip (link)}} {{#Comment Link to ReversingLabs IP report}}"
        }
      }
    },
    "url": {
      "obj:fetch": [
        "/api/network-threat-intel/url/"
      ],
      "domain": "{{#ref domain (domain)}} {{#Comment Domain portion of URL for correlation}}",
      "url-object": {
        "obj:type": "url",
        "obj:comment": "ReversingLabs Enriched URL IOC Object - {{#ref requested_url}}",
        "!url": "{{#ref requested_url (url)}} {{#Comment The full URL that was queried}}",
        "first-seen": "{{#ref first_seen}} {{#Comment First observation timestamp}}",
        "last-seen": "{{#ref last_seen}} {{#Comment Most recent observation timestamp}}",
        "text#0": "{{#ref threat_name | classification}} {{#Comment Threat classification}}",
        "text#1": "{{#ref classification}} {{#Comment Threat classification}}",
        "text#2": "{{#ref riskscore}} {{#Comment Risk score (0-10)}}",
        "text#3": "{{#ref reason}} {{#Comment Threat reason}}",
        "host": "{{#ref domain}} {{#Comment Host/domain portion of URL}}",
        "scheme": "{{#ref scheme}} {{#Comment URL scheme (http/https)}}",
        "port": "{{#ref (int) port}} {{#Comment Port number, if specified}}",
        "fragment": "{{#ref fragment}} {{#Comment URL fragment, if present}}",
        "rl:classification": "{{#ref classification}} {{#Comment Threat classification}}",
        "rl:riskscore": "{{#ref riskscore}} {{#Comment Risk score (0-10)}}",
        "rl:threat_level": "{{#ref threat_level}} {{#Comment Threat level category}}",
        "rl:trust_factor": "{{#ref trust_factor}} {{#Comment Trust factor score}}",
        "rl:threat_name": "{{#ref threat_name}} {{#Comment Threat name score}}",
        "rl:reason": "{{#ref reason}} {{#Comment Threat reason}}",
        "rl:threat[]": "{{#foreach top_threats}}{{#ref threat_name}}{{/foreach}} {{#Comment Tags for each threat name}}",
        "rl:malware-family[]": "{{#foreach top_threats}}{{#ref threat_family}}{{/foreach}} {{#Comment Tags for each threat family}}",
        "obj:analysed-with->": [
          "url-analysis"
        ],
        "url-analysis": {
          "obj:type": "report",
          "obj:comment": "ReversingLabs URL Report - {{#ref requested_url}}",
          "title": "ReversingLabs URL Report",
          "type": "threat-intelligence",
          "summary": "{{#summary}} {{#Comment Unified summary for all IOC types}}",
          "link": "{{#build_link url (link)}} {{#Comment Link to ReversingLabs URL report}}"
        }
      }
    }
  }
}
EMBEDDED_MAPPINGS = ""  # legacy placeholder (raw mappings embedded above)
EMBEDDED_KEY = "rl_misp"

import base64
import ipaddress
import json
import os
import re
import requests
import uuid
import zlib
from pathlib import Path
from pymisp import MISPAttribute, MISPObject
from requests.adapters import HTTPAdapter
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import quote
from urllib3.util.retry import Retry


# ============================================================
# utils.py
# ============================================================
"""Shared utilities for ReversingLabs MISP enrichment module.

Provides core utility functions for:
- IOC type detection and validation
- Hash normalization and formatting
- URL defanging/refanging
- Data sanitization and processing
"""


def detect_ioc_type(value: str) -> Optional[str]:
    """Detect IOC type from value string.

    Args:
        value: The IOC value to classify

    Returns:
        One of: 'file', 'ip', 'url', 'domain', or None if unknown
    """
    if not value or not isinstance(value, str):
        return None

    value = value.strip()

    # SHA256 (64 hex chars)
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "file"

    # SHA1 (40 hex chars)
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "file"

    # MD5 (32 hex chars)
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "file"

    # URL (starts with http/https)
    if value.startswith(("http://", "https://")):
        return "url"

    # IP address detection - use ipaddress for robust validation
    try:
        ipaddress.ip_address(value)
        return "ip"
    except Exception:
        pass

    # Domain (contains dot, not an IP, not a URL)
    if "." in value and not value[0].isdigit():
        return "domain"

    return None


def normalize_hash(value: str) -> str:
    """Normalize a hash value to lowercase.

    Args:
        value: Hash string

    Returns:
        Lowercase, stripped hash
    """
    return value.lower().strip() if value else ""


def refang_ioc(value: str) -> str:
    """Convert defanged IOC back to normal form.

    Handles common defanging patterns:
    - hxxp -> http
    - [.] -> .
    - [://] -> ://

    Args:
        value: Potentially defanged IOC

    Returns:
        Refanged IOC
    """
    if not value:
        return value

    result = value
    result = result.replace("hxxp", "http")
    result = result.replace("hXXp", "http")
    result = result.replace("[.]", ".")
    result = result.replace("[://]", "://")
    result = result.replace("[:]", ":")
    result = result.replace("[/]", "/")

    return result


def build_session(
    retries: int = 3, backoff: float = 0.3, status_forcelist=(429, 500, 502, 503, 504)
) -> requests.Session:
    """Create a requests.Session configured with retries and backoff.

    Returns a session with an HTTPAdapter that retries on common transient errors.
    """
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ============================================================
# endpoints.py
# ============================================================
"""ReversingLabs API endpoint definitions.

Centralized endpoint management for ReversingLabs threat intelligence APIs:
- File analysis endpoints (Spectra Analyze/TI Cloud)
- Domain/IP/URL reputation endpoints
- Dynamic endpoint resolution based on IOC type
- Template-based URL construction with parameter substitution
"""

# Endpoint templates with placeholders (include /api/ prefix)
ENDPOINTS: Dict[str, str] = {
    "file:details": "/api/samples/v2/list/details/",
    "file:classification": "/api/samples/v3/{hash}/classification/",
    "domain": "/api/network-threat-intel/domain/{domain}/",
    "url": "/api/network-threat-intel/url/",
    "ip": "/api/network-threat-intel/ip/{ip}/report/",
}


def get_endpoint(name: str, **kwargs) -> str:
    """Get endpoint path with variable substitutions.

    Args:
        name: Endpoint key (e.g., 'file:details', 'domain')
        **kwargs: Substitution values (e.g., hash='abc123', domain='example.com')

    Returns:
        Formatted endpoint path

    Example:
        >>> get_endpoint('domain', domain='example.com')
        '/api/network-threat-intel/domain/example.com/'
    """
    template = ENDPOINTS.get(name, "")
    if not template:
        raise ValueError(f"Unknown endpoint: {name}")
    return template.format(**kwargs) if kwargs else template


def get_endpoint_for_ioc(ioc_type: str) -> str:
    """Get the primary endpoint name for an IOC type.

    Args:
        ioc_type: One of 'file', 'domain', 'ip', 'url'

    Returns:
        Endpoint key to use for this IOC type
    """
    mapping = {
        "file": "file:details",
        "domain": "domain",
        "ip": "ip",
        "url": "url",
    }
    return mapping.get(ioc_type, "")


# ============================================================
# walker.py
# ============================================================
"""JSON path traversal engine with fallback support.

Provides robust utilities for traversing nested JSON structures with:
- Dot notation path support
- Fallback path arrays for resilience
- Type coercion capabilities
- Array iteration support
- Safe navigation with defaults
"""


def deep_get(data: dict, path: str, default: Any = None) -> Any:
    """Get nested value using dot notation.

    Args:
        data: Dictionary to traverse
        path: Dot-separated path (e.g., 'sample_summary.classification')
        default: Value to return if path not found

    Returns:
        Value at path, or default if not found

    Example:
        >>> deep_get({'a': {'b': {'c': 'value'}}}, 'a.b.c')
        'value'
    """
    if not data or not path:
        return default

    keys = path.split(".")
    result = data

    for key in keys:
        if isinstance(result, dict):
            # Support bracket index syntax like 'array[0]'
            m = re.match(r"^([^\[]+)\[(\d+)\]$", key)
            if m:
                key_name = m.group(1)
                idx = int(m.group(2))
                result = result.get(key_name)
                if not isinstance(result, list):
                    return default
                result = result[idx] if 0 <= idx < len(result) else None
            else:
                result = result.get(key)
        elif isinstance(result, list) and key.isdigit():
            idx = int(key)
            result = result[idx] if 0 <= idx < len(result) else None
        else:
            return default

        if result is None:
            return default

    return result


def get_first(data: dict, paths: List[str], default: Any = None) -> Any:
    """Try multiple paths, return first non-None value.

    Args:
        data: Dictionary to traverse
        paths: List of dot-separated paths to try in order
        default: Value to return if all paths fail

    Returns:
        First non-None value found, or default

    Example:
        >>> get_first({'fallback': 'found'}, ['primary', 'fallback'])
        'found'
    """
    for path in paths:
        value = deep_get(data, path)
        if value is not None:
            return value
    return default


def coerce(value: Any, type_name: str) -> Any:
    """Coerce value to specified type.

    Args:
        value: Value to coerce
        type_name: Target type ('int', 'str', 'bool', 'float')

    Returns:
        Coerced value, or None if coercion fails
    """
    if value is None:
        return None

    try:
        if type_name == "int":
            return int(value)
        if type_name == "str":
            return str(value)
        if type_name == "bool":
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes")
            return bool(value)
        if type_name == "float":
            return float(value)
    except (ValueError, TypeError):
        return None

    return value


def iterate_array(data: dict, array_path: str) -> List[dict]:
    """Get array at path for iteration.

    Args:
        data: Dictionary containing array
        array_path: Dot-separated path to array

    Returns:
        List of items, or empty list if not found/not an array
    """
    result = deep_get(data, array_path, [])
    if isinstance(result, list):
        return result
    return []


def filter_by_field(items: List[dict], field: str, value: Any) -> List[dict]:
    """Filter list of dicts by field value.

    Args:
        items: List of dictionaries
        field: Field name to check
        value: Value to match

    Returns:
        Filtered list

    Example:
        >>> filter_by_field([{'type': 'A'}, {'type': 'MX'}], 'type', 'A')
        [{'type': 'A'}]
    """
    return [item for item in items if item.get(field) == value]


def extract_field(items: List[dict], field: str) -> List[Any]:
    """Extract a field value from each dict in list.

    Args:
        items: List of dictionaries
        field: Field name to extract

    Returns:
        List of extracted values (excluding None)
    """
    return [item.get(field) for item in items if item.get(field) is not None]


# ============================================================
# misp_builder.py
# ============================================================
"""MISP object and attribute builder using pymisp.

Creates properly structured MISP objects and attributes with automatic type detection.
Ensures compatibility with MISP's expected format and validation requirements.

Features:
- Automatic MISP type detection for attributes
- Custom object support with proper MISP structure
- Relationship and reference management
- Tag creation with namespace support
- Full pymisp compatibility with dict-based return format
"""


def create_misp_object(
    name: str,
    attributes: List[Dict[str, Any]],
    template_uuid: Optional[str] = None,
    comment: str = "",
) -> Dict[str, Any]:
    """Create a MISP object using pymisp, returned as a dict.

    Uses pymisp internally to ensure proper structure (template_uuid,
    template_version, distribution, sharing_group_id, etc.) but returns
    a dict for compatibility with existing code.

    Args:
        name: Object type name (e.g., 'file', 'domain-ip')
        attributes: List of attribute dictionaries with keys:
            - type: MISP type
            - value: attribute value
            - object_relation: relation name
            - category: optional category
            - comment: optional comment
            - to_ids: optional IDS flag
        template_uuid: Override template UUID (uses pymisp default if None)
        comment: Optional object comment

    Returns:
        MISP object dictionary with proper structure
    """
    obj = MISPObject(name, standalone=False)

    if comment:
        obj.comment = comment

    # Add attributes
    for attr_def in attributes:
        attr_type = attr_def.get("type")  # This may be object_relation or actual MISP type
        value = attr_def.get("value")
        object_relation = attr_def.get("object_relation")
        category = attr_def.get("category")
        attr_comment = attr_def.get("comment", "")
        to_ids = attr_def.get("to_ids", False)

        if not value:
            continue

        # Use object_relation if provided, otherwise use attr_type as the relation
        relation = object_relation or attr_type

        # Build kwargs - let pymisp infer type from object template when possible
        kwargs = {"value": value}

        # Only pass explicit type if it's a known MISP type (not an object relation name)
        # Object relations like 'first-seen', 'last-seen' should NOT be passed as type
        known_misp_types = {
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "ssdeep",
            "imphash",
            "tlsh",
            "filename",
            "size-in-bytes",
            "text",
            "link",
            "datetime",
            "domain",
            "ip-src",
            "ip-dst",
            "url",
            "hostname",
            "port",
            "comment",
            "counter",
            "boolean",
            "float",
            "hex",
            "mime-type",
            "entropy",
        }
        if attr_type and attr_type in known_misp_types:
            kwargs["type"] = attr_type

        if category:
            kwargs["category"] = category
        if attr_comment:
            kwargs["comment"] = attr_comment
        kwargs["to_ids"] = to_ids

        obj.add_attribute(relation, **kwargs)

    # Serialize to dict via JSON (ensures all pymisp fields are present)
    obj_dict = json.loads(obj.to_json())

    # Match v0 working format: keep distribution/sharing_group_id as strings
    # and add required fields

    # Fix boolean values in attributes and add strict field (v0 format)
    for attr in obj_dict.get("Attribute", []):
        if "disable_correlation" in attr:
            attr["disable_correlation"] = bool(
                attr["disable_correlation"]
            )  # Keep as boolean like v0
        if "to_ids" in attr:
            attr["to_ids"] = bool(attr["to_ids"])  # Keep as boolean like v0
        # Add strict field to match v0 working format
        attr["strict"] = False

    # Add object_name field to match v0 working format
    obj_dict["object_name"] = obj_dict.get("name")

    return obj_dict


def create_misp_attribute(
    misp_type: str,
    value: Any,
    category: str = "Other",
    comment: str = "",
    object_relation: Optional[str] = None,
    to_ids: bool = False,
) -> Dict[str, Any]:
    """Create a MISP attribute dictionary for use in objects.

    This returns a dict that can be passed to create_misp_object's attributes list.

    Args:
        misp_type: MISP attribute type (e.g., 'md5', 'ip-src', 'domain')
        value: Attribute value
        category: MISP category (e.g., 'Payload delivery', 'Network activity')
        comment: Optional comment
        object_relation: Object relation for object attributes
        to_ids: Whether this attribute should be used for IDS

    Returns:
        Attribute dictionary
    """
    attr = {
        "type": misp_type,
        "value": value,
        "category": category,
        "to_ids": to_ids,
    }

    if comment:
        attr["comment"] = comment

    if object_relation:
        attr["object_relation"] = object_relation

    return attr


def create_tag(namespace: str, key: str, value: str) -> Dict[str, str]:
    """Create a MISP tag in namespace:key="value" format.

    Args:
        namespace: Tag namespace (e.g., 'rl')
        key: Tag key (e.g., 'classification')
        value: Tag value (e.g., 'malicious')

    Returns:
        MISP tag dictionary

    Example:
        >>> create_tag('rl', 'classification', 'malicious')
        {'name': 'rl:classification="malicious"'}
    """
    return {"name": f'{namespace}:{key}="{value}"'}


def create_object_reference(
    source_uuid: str,
    target_uuid: str,
    relationship_type: str = "related-to",
) -> Dict[str, str]:
    """Create a MISP object reference (relationship).

    Note: When using pymisp objects, use obj.add_reference() instead.

    Args:
        source_uuid: UUID of source object
        target_uuid: UUID of target object
        relationship_type: Type of relationship (e.g., 'related-to', 'contains')

    Returns:
        MISP object reference dictionary in v0 compatible format
    """
    return {
        "uuid": str(uuid.uuid4()),
        "object_uuid": source_uuid,  # v0 format uses object_uuid instead of source_uuid
        "referenced_uuid": target_uuid,
        "relationship_type": relationship_type,
    }


def build_results_container() -> Dict[str, List]:
    """Create an empty results container for module output.

    Returns:
        Dictionary with Object, Attribute, Tag lists
    """
    return {
        "Object": [],
        "Attribute": [],
        "Tag": [],
        "ObjectReference": [],
    }


# ============================================================
# loader.py
# ============================================================
"""Mapping loader with support for encoded embedded mappings.

In compiled artifacts, mappings are embedded as a compressed+XOR+base64
string (`EMBEDDED_MAPPINGS`) along with an `EMBEDDED_KEY`. During
development, the JSON file on disk or a provided `MAPPING_RULES` dict is
used instead.
"""


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _decode_embedded(encoded: str, key: str) -> Dict[str, Any]:
    """Decode embedded mapping string (v=...|d=...|<b64>) into a dict."""
    payload = encoded or ""
    if isinstance(payload, str) and payload.startswith("v=") and "|" in payload:
        payload = payload.split("|")[-1]

    decoded = base64.b64decode(payload)
    key_bytes = key.encode("utf-8")
    unxored = _xor_bytes(decoded, key_bytes)
    decompressed = zlib.decompress(unxored)
    return json.loads(decompressed.decode("utf-8"))


def load_mappings(path: Optional[str] = None) -> Dict[str, Any]:
    """Load mappings from embedded payload, in-memory dict, or JSON file.

    Priority:
    1. Native `MAPPING_RULES` dict (development/testing convenience and raw-embedded builds)
    2. Embedded encoded mapping (`EMBEDDED_MAPPINGS` + `EMBEDDED_KEY`)
    3. JSON file at `path`
    """

    if "MAPPING_RULES" in globals() and isinstance(globals()["MAPPING_RULES"], dict):
        return globals()["MAPPING_RULES"]

    if globals().get("EMBEDDED_MAPPINGS"):
        key = globals().get("EMBEDDED_KEY", "rl_misp")
        return _decode_embedded(globals()["EMBEDDED_MAPPINGS"], key)

    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    raise ValueError("No mappings available - provide a path or compile the module")


def strip_comments(mappings: Any) -> Any:
    """Recursively remove comment keys (starting with '#')."""
    if isinstance(mappings, dict):
        return {k: strip_comments(v) for k, v in mappings.items() if not k.startswith("#")}
    if isinstance(mappings, list):
        return [strip_comments(i) for i in mappings]
    return mappings


def get_ioc_mappings(mappings: Dict, ioc_type: str) -> Dict[str, Any]:
    """Return IOC-specific mappings with comments stripped.

    Supports both 'create' (preferred) and '_enrich' (legacy) top-level keys.
    """
    enrich_section = mappings.get("create") or mappings.get("_enrich", {})
    ioc_mappings = enrich_section.get(ioc_type, {})
    return strip_comments(ioc_mappings)


def get_mapping_version(version_str: Optional[str] = None) -> Optional[str]:
    """Extract version (v=X.X.X) from an encoded mapping header."""
    payload = version_str if version_str is not None else globals().get("EMBEDDED_MAPPINGS")
    if not payload or not isinstance(payload, str):
        return None

    if payload.startswith("v=") and "|" in payload:
        for part in payload.split("|"):
            if part.startswith("v=") and len(part) > 2:
                return part[2:]

    return None


# ============================================================
# handler.py
# ============================================================
"""MISP module handler - main entry point.

Core enrichment handler for ReversingLabs threat intelligence integration.
Provides comprehensive IOC enrichment with automatic MISP type detection,
custom object support, and relationship management.

Features:
- Automatic MISP attribute type detection (text, float, boolean, datetime)
- Declarative JSON mappings with handler system
- MISP object relationships (analysed-with, related-to, contains)
- Comprehensive error handling and validation

Follows MISP module conventions with introspection dict and handler function.
"""


# Relationship type constants for MISP object references
RELATIONSHIP_TYPES = {
    "ANALYSED_WITH": "analysed-with",  # Objects link to analysis reports
    "RELATED_TO": "related-to",  # General relationship between objects
    "CONTAINS": "contains",  # Parent object contains child objects
}

# Safety throttle: maximum number of synthesized child objects to create
# from DNS records to avoid excessive correlations in MISP events.
# Can be raised/lowered if you need more or fewer synthesized children.
MAX_DNS_CHILDREN = 25

# Default maximum iterations for foreach loops and object iteration.
# Can be overridden per-field with limit syntax: {{#foreach path 10}} or objects[10]
MAX_FOREACH_ITERATIONS = 50

# Parent-child relationship patterns for dynamic object creation
# These define the relationship type to use when linking a parent object
# to its NESTED CHILDREN (not siblings). The key is the parent type,
# and the value maps child type -> relationship type.
# NOTE: These are applied via DYNAMIC_RELATIONSHIPS, not as pending refs.
OBJECT_RELATIONSHIPS = {
    # IOC root objects don't need entries here since they use
    # obj:analysed-with-> directives in the mapping to link to children.
}

# Dynamic child relationship patterns (created via handlers or nesting)
# These define what relationship type to use when a parent creates/contains
# a child object of a specific type. Only needed for handler-created children
# that don't have explicit obj:related-to-> or obj:analysed-with-> in the mapping.
DYNAMIC_RELATIONSHIPS = {
    # DNS record contains synthesized domain-ip/ip-port from iterate_dns handler
    "dns-record": {
        "domain-ip": RELATIONSHIP_TYPES["CONTAINS"],
        "ip-port": RELATIONSHIP_TYPES["CONTAINS"],
    }
}


# Deterministic UUID helpers to support object reuse across enrichments
def _first_attr_value(attributes: List[Dict[str, Any]], relations: List[str]) -> Optional[str]:
    for rel in relations:
        for a in attributes:
            if str(a.get("object_relation", "")).lower() == rel:
                val = a.get("value")
                if val is None:
                    continue
                sval = str(val).strip()
                if sval:
                    return sval
    return None


def _normalize_domain(value: str) -> str:
    v = str(value).strip().lower()
    if v.endswith("."):
        v = v[:-1]
    return v


def _compute_deterministic_uuid(
    obj_type: str,
    attributes: List[Dict[str, Any]],
    original_value: str,
    ioc_type: Optional[str] = None,
) -> Optional[str]:
    """Compute deterministic UUID for object deduplication.

    DISABLED: Deterministic UUIDs were causing MISP to silently drop objects.
    PyMISP-generated random UUIDs work correctly. Keeping function signature
    for future investigation.
    """
    return None
    # Original implementation preserved for reference:
    # try:
    #     ident: Optional[str] = None
    #     if obj_type == 'domain-ip':
    #         ident = _first_attr_value(attributes, ["domain", "hostname"]) or (
    #             _normalize_domain(original_value) if ioc_type in ("domain", "url") else None
    #         )
    #         if ident:
    #             ident = _normalize_domain(ident)
    #     elif obj_type == 'ip-port':
    #         ident = _first_attr_value(attributes, ["ip", "ip-dst", "ip-src"]) or (
    #             original_value if ioc_type == "ip" else None
    #         )
    #         if ident:
    #             ident = str(ident).strip()
    #     elif obj_type == 'dns-record':
    #         ident = _first_attr_value(attributes, ["queried-domain"]) or (
    #             _normalize_domain(original_value) if ioc_type in ("domain", "url") else None
    #         )
    #         if ident:
    #             ident = _normalize_domain(ident)
    #     if not ident:
    #         return None
    #     name = f"https://reversinglabs.com/misp/{obj_type}/{ident}"
    #     return str(uuid.uuid5(uuid.NAMESPACE_URL, name))
    # except Exception:
    #     return None


def _add_child_object_with_limit(
    *,
    child_obj_name: str,
    child_key: str,
    attrs: List[Dict[str, Any]],
    child_objects: List[Tuple[str, Dict[str, Any]]],
    results: Dict[str, Any],
    created_children: int,
    limit: int,
    truncated_tag_emitted: bool,
    note_label: str,
    original_value: str = "",
    ioc_type: Optional[str] = None,
) -> Tuple[int, bool, Optional[Dict[str, Any]]]:
    """Append a child object respecting a truncate limit with one-note tagging.

    Also checks for existing objects by deterministic UUID and merges instead of
    duplicating.
    """
    if not attrs:
        return created_children, truncated_tag_emitted, None

    if created_children >= limit:
        if not truncated_tag_emitted:
            try:
                results["Tag"].append(
                    create_tag("rl", "note", f"{note_label} truncated after {limit} items")
                )
            except Exception:
                pass
            truncated_tag_emitted = True
        return created_children, truncated_tag_emitted, None

    child_obj = create_misp_object(child_obj_name, attrs)

    # Compute deterministic UUID for reuse
    det_uuid = _compute_deterministic_uuid(child_obj_name, attrs, original_value, ioc_type)
    if det_uuid:
        child_obj["uuid"] = det_uuid
        # Check if object with same UUID exists and merge
        existing_obj = next(
            (o for o in results.get("Object", []) if o.get("uuid") == det_uuid), None
        )
        if existing_obj:
            # Merge attributes with dedup
            existing_attrs = existing_obj.get("Attribute", [])
            seen_pairs = {
                (str(a.get("object_relation", "")).lower(), str(a.get("value")))
                for a in existing_attrs
            }
            for a in child_obj.get("Attribute", []):
                key = (str(a.get("object_relation", "")).lower(), str(a.get("value")))
                if key not in seen_pairs:
                    existing_attrs.append(a)
                    seen_pairs.add(key)
            existing_obj["Attribute"] = existing_attrs
            child_objects.append((child_key, existing_obj))
            return created_children, truncated_tag_emitted, existing_obj

    results["Object"].append(child_obj)
    child_objects.append((child_key, child_obj))
    return created_children + 1, truncated_tag_emitted, child_obj


# IOC type configuration: defines all type-specific behaviors in one place
# This eliminates repeated conditionals throughout the code
IOC_TYPE_CONFIG = {
    "file": {
        "param_name": "hash",
        "value_fields": ["sample_summary.sha1", "sha1"],
        "link_template": "{api_url}/{value}/",
        "normalize": normalize_hash,
        "request_method": "POST",
        "request_body": lambda val: {"hash_values": [val]},
    },
    "domain": {
        "param_name": "domain",
        "value_fields": ["requested_domain", "domain"],
        "link_template": "{api_url}/domain/{value}/analysis/domain/",
        "normalize": None,
        "request_method": "GET",
    },
    "ip": {
        "param_name": "ip",
        "value_fields": ["requested_ip", "ip"],
        "link_template": "{api_url}/ip/{value}/analysis/ip/",
        "normalize": None,
        "request_method": "GET",
    },
    "url": {
        "param_name": "url",
        "value_fields": ["requested_url", "url"],
        "link_template": None,
        "normalize": None,
        "request_method": "GET",
        "request_params": lambda val: {"url": val},
    },
}

# Map MISP attribute relation names to owning object types for merge decisions
RELATION_TO_OBJECT_TYPE = {
    # Domain/hostname relations belong to domain-ip objects
    "domain": "domain-ip",
    "hostname": "domain-ip",
    "requested_domain": "domain-ip",
    "queried-domain": "dns-record",  # specific to dns-record object
    # IP relations belong to ip-port objects
    "ip": "ip-port",
    "ip-dst": "ip-port",
    "ip-src": "ip-port",
    "requested_ip": "ip-port",
    # URL relations belong to url objects
    "url": "url",
    "requested_url": "url",
    # DNS record value relations belong to dns-record objects
    "a-record": "dns-record",
    "aaaa-record": "dns-record",
    "cname-record": "dns-record",
    "mx-record": "dns-record",
    "ns-record": "dns-record",
    "txt-record": "dns-record",
    "soa-record": "dns-record",
    "srv-record": "dns-record",
    "ptr-record": "dns-record",
}

# Map MISP object_relation names to IOC types for enrichment
# Used when enriching attributes that are part of objects (e.g., domain-ip object)
MISP_TYPE_MAPPING = {
    "domain": "domain",
    "hostname": "domain",
    "ip": "ip",
    "ip-dst": "ip",
    "ip-src": "ip",
    "url": "url",
    "requested_domain": "domain",
    "requested-domain": "domain",
    "queried-domain": "domain",
    "requested_ip": "ip",
    "requested_url": "url",
}


def _parse_spf_for_endpoints(txt: str) -> List[Tuple[str, str]]:
    """Extract endpoint candidates from an SPF/TXT record string.

    Returns a list of (ptype, value) tuples where ptype is 'ip' or 'domain'.
    """
    results: List[Tuple[str, str]] = []
    if not txt or not isinstance(txt, str):
        return results

    s = txt.strip()
    low = s.lower()

    # Quick check for SPF signature or common tokens
    if not (
        "v=spf1" in low
        or re.search(r"ip4:|ip6:|a:|include:", low)
        or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
    ):
        return results

    # Regex to find ip4/ip6 tokens
    ip4_re = re.compile(r"ip4:([^\s;,\)]+)", flags=re.IGNORECASE)
    ip6_re = re.compile(r"ip6:([^\s;,\)]+)", flags=re.IGNORECASE)

    # Capture explicit ip4/ip6 occurrences
    for m in ip4_re.finditer(s):
        candidate = re.sub(r"^[\"']+|[\"']+$", "", m.group(1).strip())
        ip = candidate.split("/")[0]  # Strip CIDR notation
        try:
            ipaddress.ip_address(ip)
            results.append(("ip", ip))
        except Exception:
            continue

    for m in ip6_re.finditer(s):
        candidate = re.sub(r"^[\"']+|[\"']+$", "", m.group(1).strip())
        ip = candidate.split("/")[0]
        try:
            ipaddress.ip_address(ip)
            results.append(("ip", ip))
        except Exception:
            continue

    # Parse a: and include: tokens
    tokens = re.split(r"\s+", s)
    for tok in tokens:
        tl = tok.lower()
        if tl.startswith("a:"):
            host = tok.split(":", 1)[1]
            host = re.sub(r"^[\"']+|[\"']+$", "", host.strip()).rstrip(".,;)")
            if re.match(r"^[A-Za-z0-9\.-]+$", host) and "." in host:
                results.append(("domain", host.lower()))
        elif tl.startswith("include:"):
            host = tok.split(":", 1)[1].strip()
            host = re.sub(r"^[\"']+|[\"']+$", "", host).rstrip(".,;)")
            if re.match(r"^[A-Za-z0-9\.-]+$", host) and "." in host:
                results.append(("domain", host.lower()))

    # Deduplicate
    seen: Set[Tuple[str, str]] = set()
    dedup: List[Tuple[str, str]] = []
    for ptype, val in results:
        key = (ptype, val.lower())
        if key in seen:
            continue
        seen.add(key)
        dedup.append((ptype, val))

    return dedup


def _deduplicate_tags(results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate tags from results.

    Tags are considered duplicates if they have the same 'name' value.
    Keeps the first occurrence of each tag.
    """
    if "Tag" not in results:
        return results

    seen_names: Set[str] = set()
    deduped: List[Dict[str, Any]] = []

    for tag in results["Tag"]:
        name = tag.get("name", "")
        if name and name not in seen_names:
            seen_names.add(name)
            deduped.append(tag)

    results["Tag"] = deduped
    return results


def _deduplicate_object_attributes(results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate attributes within each object.

    Duplicates are determined by the tuple (object_relation, value, type)
    so repeated copies of the same attribute value are collapsed while
    preserving order of first occurrence.
    """
    objects = results.get("Object")
    if not objects:
        return results

    for obj in objects:
        attrs = obj.get("Attribute")
        if not attrs:
            continue

        seen: Set[Tuple[str, str, str]] = set()
        deduped: List[Dict[str, Any]] = []

        for attr in attrs:
            key = (
                str(attr.get("object_relation", "")).lower(),
                str(attr.get("value")),
                str(attr.get("type", "")).lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(attr)

        obj["Attribute"] = deduped

    return results


def _find_local_config() -> Optional[Path]:
    """Search for `local.config.json` starting from several likely locations.

    Order of lookup:
    - current working directory
    - the directory of this file and its parents (useful when running compiled dist)
    - None if not found
    """
    # Check current working dir first
    cwd = Path.cwd()
    candidate = cwd / "local.config.json"
    if candidate.exists():
        return candidate

    # Walk upward from this file's location (handles compiled single-file in dist)
    this_path = Path(__file__).resolve()
    for parent in [this_path.parent] + list(this_path.parents):
        cfg = parent / "local.config.json"
        if cfg.exists():
            return cfg

    return None


# MISP module metadata
moduleinfo = {
    "version": "1.0.0",
    "author": "ReversingLabs",
    "description": "ReversingLabs threat intelligence enrichment module",
    "module-type": ["expansion"],
    "name": "ReversingLabs",
    "logo": "reversinglabs.png",
    "references": ["https://github.com/reversinglabs/reversinglabs-misp"],
    "support": "support@reversinglabs.com",
}

# moduleconfig is the canonical list MISP-modules reads to determine
# which config keys to prompt for and pass to the handler
moduleconfig = ["api_url", "api_token", "verify_ssl"]

# Custom modules need config in moduleinfo for misp-modules to expose it
moduleinfo["config"] = moduleconfig

mispattributes = {
    "input": ["md5", "sha1", "sha256", "domain", "hostname", "ip", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}


def _parse_api_response(response: requests.Response, url: str) -> Dict[str, Any]:
    """Parse API response, raising on HTTP errors or invalid JSON.

    Args:
        response: requests.Response object
        url: Request URL (for error messages)

    Returns:
        Parsed JSON data as dictionary

    Raises:
        requests.RequestException: On HTTP errors or invalid JSON
    """
    if not response.ok:
        try:
            err_detail = response.text[:500]
        except Exception:
            err_detail = f"HTTP {response.status_code}"
        raise requests.RequestException(f"HTTP {response.status_code}: {err_detail}")

    try:
        return response.json()
    except json.JSONDecodeError:
        content_preview = response.text[:200] if response.text else "(empty)"
        raise requests.RequestException(
            f"API returned invalid JSON (HTTP {response.status_code}). "
            f"URL: {url}. Preview: {content_preview}"
        ) from None


def _get_endpoint_config(mappings: Dict, ioc_type: str) -> List[str]:
    """Get endpoint templates from mappings for an IOC type.

    Args:
        mappings: Full mappings dictionary
        ioc_type: IOC type (file, domain, ip, url)

    Returns:
        List of endpoint URL templates to try in order
    """
    # Prefer 'create', fall back to '_enrich' for backward compatibility
    enrich_section = mappings.get("create") or mappings.get("_enrich", {})
    ioc_mappings = enrich_section.get(ioc_type, {})

    # Get endpoints from obj:fetch (array form)
    endpoints = ioc_mappings.get("obj:fetch", [])

    # obj:fetch with dict value is a nested fetch, not top-level endpoints
    if isinstance(endpoints, dict):
        endpoints = []
    elif isinstance(endpoints, str):
        endpoints = [endpoints]

    return list(endpoints)


def _resolve_endpoint(template: str, **kwargs) -> str:
    """Resolve endpoint template with parameter substitution.

    Args:
        template: URL template with {placeholders}
        **kwargs: Substitution values

    Returns:
        Resolved endpoint path
    """
    return template.format(**kwargs) if kwargs else template


def _fetch_with_endpoint_fallback(
    session: requests.Session,
    api_url: str,
    ioc_type: str,
    ioc_value: str,
    headers: Dict[str, str],
    verify_ssl: bool,
    endpoints: List[str],
) -> Dict[str, Any]:
    """Fetch data trying endpoints in order until one succeeds.

    Args:
        session: Configured requests session
        api_url: ReversingLabs API base URL
        ioc_type: IOC type being enriched
        ioc_value: The IOC value
        headers: HTTP headers including auth token
        verify_ssl: Whether to verify SSL certificates
        endpoints: List of endpoint URL templates to try in order

    Returns:
        Parsed API response data

    Raises:
        requests.RequestException: If all endpoints fail
    """
    last_error = None

    for template in endpoints:
        # Determine endpoint name from template for response normalization
        if "/v2/list/details" in template:
            endpoint_name = "file:details"
        elif "/v3/" in template and "/classification" in template:
            endpoint_name = "file:classification"
        else:
            endpoint_name = ioc_type

        # Build substitution kwargs based on IOC type using config
        config = IOC_TYPE_CONFIG.get(ioc_type, {})
        param_name = config.get("param_name")
        kwargs = {param_name: ioc_value} if param_name else {}

        endpoint_path = _resolve_endpoint(template, **kwargs)
        url = f"{api_url}{endpoint_path}"

        try:
            # Build request based on IOC type configuration
            type_config = IOC_TYPE_CONFIG.get(ioc_type, {})
            request_kwargs = {"headers": headers, "verify": verify_ssl, "timeout": 30}

            if endpoint_name == "file:details" and "request_body" in type_config:
                request_kwargs["json"] = type_config["request_body"](ioc_value)
                response = session.post(url, **request_kwargs)
            elif "request_params" in type_config:
                request_kwargs["params"] = type_config["request_params"](ioc_value)
                response = session.get(url, **request_kwargs)
            else:
                response = session.get(url, **request_kwargs)

            if response.ok:
                data = response.json()

                # Normalize response format
                normalized = _normalize_api_response(data, endpoint_name, ioc_type)
                # Treat explicit None as "no data" and continue, but accept
                # empty dicts/lists as valid responses (do not rely on truthiness).
                if normalized is not None:
                    return normalized
                # If normalization returned None, try next endpoint
                continue

        except requests.RequestException as e:
            last_error = e
            continue

    # All endpoints failed
    if last_error:
        raise last_error
    raise requests.RequestException(f"No valid data from any endpoint for {ioc_type}: {ioc_value}")


def _normalize_api_response(data: Dict, endpoint_name: str, ioc_type: str) -> Optional[Dict]:
    """Normalize API response to consistent format for mappings.

    Args:
        data: Raw API response
        endpoint_name: The endpoint that returned this data
        ioc_type: IOC type being enriched

    Returns:
        Normalized data dict, or None if response indicates no data
    """
    if ioc_type == "file":
        if endpoint_name == "file:details":
            # Spectra Analyze format: {"count": N, "results": [...]}
            if "results" in data and isinstance(data["results"], list) and data["results"]:
                return data["results"][0]
            # TI Cloud format: {"rl": {"samples": [...]}}
            if "rl" in data:
                samples = data.get("rl", {}).get("samples", [])
                if samples:
                    return samples[0]
            # No results - return None to try next endpoint
            return None
        elif endpoint_name == "file:classification":
            # v3 classification response - normalize to sample_summary format
            if "rl" in data:
                classification_data = data.get("rl", {})
            else:
                classification_data = data
            return {"sample_summary": classification_data, "_source": "classification_v3"}

    # For other IOC types, return as-is
    return data


def handler(q: Optional[str] = None) -> Dict[str, Any]:
    """Main MISP module handler.

    Args:
        q: JSON string or dict containing request from MISP

    Returns:
        Dictionary with 'results' or 'error' key
    """
    if not q:
        return {"error": "No input provided"}

    # Handle both string (JSON) and dict inputs
    if isinstance(q, dict):
        request = q
    else:
        try:
            request = json.loads(q)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON input: {e}"}

    config = request.get("config", {})

    # MISP may send config keys with module prefix (e.g., reversinglabs_spectra_analyze_api_url)
    # or without prefix (api_url). Check both patterns.
    def get_config_value(key: str) -> str:
        """Get config value checking both prefixed and unprefixed keys."""
        # Try unprefixed first
        val = config.get(key, "")
        if val:
            return val
        # Try with module name prefix (reversinglabs_spectra_analyze_key)
        prefixed_key = f"reversinglabs_spectra_analyze_{key}"
        val = config.get(prefixed_key, "")
        if val:
            return val
        # Try with full MISP prefix pattern (Enrichment_reversinglabs_spectra_analyze_key)
        full_prefixed_key = f"Enrichment_reversinglabs_spectra_analyze_{key}"
        val = config.get(full_prefixed_key, "")
        if val:
            return val
        return ""

    # Validate config
    api_url = get_config_value("api_url")
    api_token = get_config_value("api_token")

    # If api_url or api_token not provided in the request (e.g., local testing),
    # attempt to use environment variables first, then `local.config.json`.
    # Request-provided values take precedence over both.
    if not api_url or not api_token:
        # Environment variable fallback
        env_api_url = os.getenv("RL_API_URL")
        env_api_token = os.getenv("RL_API_TOKEN")
        env_verify_ssl = os.getenv("RL_VERIFY_SSL")
        if env_api_url:
            api_url = env_api_url
        if env_api_token:
            api_token = env_api_token
        if env_verify_ssl is not None:
            # allow boolean-like strings
            config["verify_ssl"] = str(env_verify_ssl).lower() not in ("false", "0", "no")

        # If env vars didn't provide values, fall back to local.config.json
        if not api_url or not api_token:
            try:
                local_cfg = _find_local_config()
                if local_cfg is not None:
                    local_data = json.loads(local_cfg.read_text(encoding="utf-8"))
                    # Merge: request config overrides local file
                    merged = {**local_data, **config}
                    api_url = merged.get("api_url", api_url)
                    api_token = merged.get("api_token", api_token)
                    # Also allow `verify_ssl` to be provided via local config
                    config = merged
            except Exception:
                pass

    # Normalize api_url: strip trailing slashes and /api suffix
    # (endpoints already include /api/ prefix)
    api_url = (api_url or "").rstrip("/")
    if api_url.endswith("/api"):
        api_url = api_url[:-4]
    if not api_url:
        return {"error": "Missing api_url in config"}
    if not api_token:
        return {"error": "Missing api_token in config"}

    # Get input attribute - MISP may send as 'attribute' (dict) or include value at top level
    attribute = request.get("attribute", {})
    if not isinstance(attribute, dict):
        attribute = {}

    # Try multiple paths where MISP might put the value
    attr_type = attribute.get("type", "") or request.get("type", "")
    attr_value = attribute.get("value", "") or request.get("value", "")

    # Also check for hash type keys at top level (e.g., {"sha256": "..."})
    if not attr_value:
        for hash_key in (
            "sha256",
            "sha1",
            "md5",
            "sha512",
            "domain",
            "ip",
            "ip-src",
            "ip-dst",
            "url",
            "hostname",
        ):
            if request.get(hash_key):
                attr_value = request.get(hash_key)
                attr_type = hash_key
                break

    if not attr_value:
        return {"error": "No attribute value provided"}

    # Refang and detect IOC type
    attr_value = refang_ioc(attr_value)
    ioc_type = detect_ioc_type(attr_value)

    if not ioc_type:
        return {"error": f"Could not determine IOC type for: {attr_value}"}

    # Check if the attribute is part of an object
    object_relation = attribute.get("object_relation")
    if object_relation:
        # Validate and map object_relation to a valid MISP type
        mapped_type = MISP_TYPE_MAPPING.get(object_relation, object_relation)
        # Prefer an explicit attribute `type` or the detected IOC type.
        # Only use the object_relation->type mapping when we have no
        # explicit `attribute.type` and `detect_ioc_type` couldn't determine
        # a type from the value.
        if mapped_type and not attribute.get("type") and not ioc_type:
            ioc_type = mapped_type

    # Ensure ioc_type is not None before proceeding
    if not ioc_type:
        return {"error": f"Could not determine valid IOC type for: {attr_value}"}

    # Normalize IOC value if normalization function exists
    type_config = IOC_TYPE_CONFIG.get(ioc_type, {})
    if normalize_func := type_config.get("normalize"):
        attr_value = normalize_func(attr_value)

    try:
        # Load mappings and perform enrichment
        mappings = load_mappings()
        results = enrich(api_url, api_token, ioc_type, attr_value, mappings, config)

        # Ensure simplified-format compatibility for MISP core (ShadowAttribute path
        # accesses results["values"] and results["types"]). Include format flag
        # alongside to avoid nesting the payload twice.
        results.setdefault("values", [attr_value])
        results.setdefault("types", [attr_type])
        results.setdefault("format", "misp_standard")

        return {"results": results}
    except requests.RequestException as e:
        return {"error": f"API request failed: {e}"}
    except Exception as e:
        return {"error": f"Enrichment failed: {e}"}


def enrich(
    api_url: str,
    api_token: str,
    ioc_type: str,
    value: str,
    mappings: Dict,
    config: Dict,
) -> Dict[str, Any]:
    """Perform enrichment using declarative mappings.

    Args:
        api_url: ReversingLabs API base URL
        api_token: API authentication token
        ioc_type: One of 'file', 'domain', 'ip', 'url'
        value: The IOC value to enrich
        mappings: Loaded mappings dictionary
        config: Module configuration

    Returns:
        MISP results dictionary with Object, Attribute, Tag lists
    """
    verify_ssl = config.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.lower() not in ("false", "0", "no")

    headers = {
        "Authorization": f"Token {api_token}",
        "Content-Type": "application/json",
    }
    # Add User-Agent including module name and version; allow env override
    try:
        mod_version = moduleinfo.get("version", "1.0.0")
    except Exception:
        mod_version = "1.0.0"
    ua_env = os.getenv("RL_USER_AGENT")
    if ua_env:
        user_agent = ua_env
    else:
        user_agent = f"ReversingLabs MISP Module version {mod_version}"
    headers["User-Agent"] = user_agent

    # Build resilient requests session (retries + backoff)
    session = build_session()

    # Get endpoint configuration from mappings
    endpoints = _get_endpoint_config(mappings, ioc_type)

    # Fetch data using endpoint fallback logic
    data = _fetch_with_endpoint_fallback(
        session, api_url, ioc_type, value, headers, verify_ssl, endpoints
    )

    # Create API context for nested endpoint calls
    context_object_type = None
    api_context = {
        "context_object_type": context_object_type,
        "session": session,
        "api_url": api_url,
        "headers": headers,
        "verify_ssl": verify_ssl,
        "original_value": value,
        "ioc_type": ioc_type,
    }

    # Apply mappings to build MISP objects
    return apply_mappings(data, mappings, ioc_type, value, api_context)


def _parse_obj_key(obj_key: str) -> tuple:
    """Parse object key to extract name, relationships, array path, filter, and limit.

    Supported formats:
        "obj_name"                               - simple object
        "array_path[]"                           - iterate over array_path, no filter (default limit 50)
        "array_path[100]"                        - iterate with explicit limit
        "array_path[field=val1,val2]"            - iterate with filter (default limit 50)
        "array_path[field=val1,val2][100]"       - iterate with filter and limit

    Relationships are now defined using obj:<rel>-> directives in object definitions.

    Returns:
        (obj_name, rels, array_path, filter_expr, limit)

    Where `rels` is a list of dicts: [{"type": RELATIONSHIP_TYPES["RELATED_TO"], "targets": ["report"]}, ...]
    """
    obj_name = obj_key
    rels: list[dict] = []
    array_path = None
    filter_expr = None
    limit = MAX_FOREACH_ITERATIONS  # Default limit

    # Check for limit suffix first: "path[filter][100]" or "path[100]"
    limit_match = re.match(r"^(.+?)\[(\d+)\]$", obj_key)
    if limit_match:
        limit = int(limit_match.group(2))
        obj_key = limit_match.group(1)  # Continue parsing without the limit suffix

    # Syntax with filter: "array_path[filter]" (no trailing [] needed)
    # Example: "last_dns_records[type=A,AAAA]"
    filter_match = re.match(r"^(\S+?)\[([^\]]+)\]$", obj_key)
    if filter_match:
        potential_filter = filter_match.group(2)
        # Only treat as filter if it contains '=' (otherwise it might be a number we already parsed)
        if "=" in potential_filter:
            array_path = filter_match.group(1)
            filter_expr = potential_filter
            obj_name = array_path
            return obj_name, rels, array_path, filter_expr, limit

    # Simple iteration syntax: "array_path[]" (no filter)
    # Example: "certificates[]"
    foreach_match = re.match(r"^(\S+?)\[\]$", obj_key)
    if foreach_match:
        array_path = foreach_match.group(1)
        obj_name = array_path
        return obj_name, rels, array_path, filter_expr, limit

    # If we extracted a limit but no other iteration syntax, treat as simple iteration with limit
    # This handles "objects[100]" where 100 is the limit
    if limit != MAX_FOREACH_ITERATIONS and array_path is None:
        # The obj_key was modified to strip the [100], so it's now the array path
        array_path = obj_key
        obj_name = array_path

    return obj_name, rels, array_path, filter_expr, limit


def _is_nested_object(key: str, value: Any) -> bool:
    """Check if a key/value pair represents a nested object definition."""
    if not isinstance(value, dict):
        return False
    # It's a nested object if it has obj:type, obj:handler, obj:path, or uses array iteration syntax
    if "[]" in key:
        return True
    if value.get("obj:type"):
        return True
    if value.get("obj:handler"):
        return True
    if value.get("obj:path"):
        return True
    # obj:fetch with dict value (has obj:uri + objects template)
    # Also supports obj:fetch[0], obj:fetch[1], etc.
    if re.match(r"^obj:fetch(\[\d+\])?$", key) and isinstance(value, dict) and value.get("obj:uri"):
        return True
    # Also check if it contains nested foreach children
    for k in value:
        if "[]" in k or (isinstance(value.get(k), dict) and value.get(k, {}).get("obj:type")):
            return True
    return False


def _matches_filter(item: Dict, filter_expr: str) -> bool:
    """Check if an item matches a filter expression.

    Filter syntax:
        "field=value1,value2" - item[field] in [value1, value2] (OR within field)
        "field1=val1;field2=val2" - multiple filters combined with AND

    Values are case-insensitive for string comparisons.
    """
    if not filter_expr:
        return True

    # Split by semicolon for multiple AND filters
    filter_parts = [f.strip() for f in filter_expr.split(";") if f.strip()]

    for part in filter_parts:
        match = re.match(r"^(\w+)=(.+)$", part)
        if not match:
            continue

        field = match.group(1)
        values = [v.strip() for v in match.group(2).split(",")]

        item_value = item.get(field)
        if item_value is None:
            return False

        # Case-insensitive comparison for strings
        item_value_str = str(item_value).upper()
        values_upper = [v.upper() for v in values]
        if item_value_str not in values_upper:
            return False  # AND logic: all filters must match

    return True


# Default timeout for nested endpoint calls (seconds)
DEFAULT_ENDPOINT_TIMEOUT = 30


def _fetch_object_endpoint(
    endpoint_template: str,
    parent_data: Dict,
    original_value: str,
    api_context: Dict,
    timeout: Optional[int] = None,
) -> Tuple[Optional[Dict], Optional[str]]:
    """Fetch data from an object-specific endpoint with graceful error handling.

    Args:
        endpoint_template: URL template with placeholders like {hash}, {domain}, etc.
        parent_data: Parent object's data for resolving placeholders
        original_value: Original IOC value
        api_context: API context with session, headers, etc.
        timeout: Request timeout in seconds (default: DEFAULT_ENDPOINT_TIMEOUT)

    Returns:
        Tuple of (data, error_message). On success: (dict, None). On failure: (None, error_string).
    """
    effective_timeout = timeout if timeout is not None else DEFAULT_ENDPOINT_TIMEOUT
    endpoint = endpoint_template  # For error messages before resolution

    try:
        session = api_context.get("session")
        api_url = api_context.get("api_url", "")
        headers = api_context.get("headers", {})
        verify_ssl = api_context.get("verify_ssl", True)

        if not session or not api_url:
            return None, "missing session or api_url"

        # Build substitution values from parent data and original value
        subs = {
            "hash": original_value,
            "domain": original_value,
            "ip": original_value,
            "url": original_value,
            "value": original_value,
        }

        # Add ALL keys from parent data (supports any placeholder)
        if isinstance(parent_data, dict):
            for key, val in parent_data.items():
                if isinstance(val, (str, int, float)) and val:
                    subs[key] = str(val)
            # Also check nested sample_summary for common patterns
            sample = parent_data.get("sample_summary", {})
            if isinstance(sample, dict):
                for key, val in sample.items():
                    if isinstance(val, (str, int, float)) and val:
                        subs[key] = str(val)
                subs["hash"] = (
                    sample.get("sha256") or sample.get("sha1") or sample.get("md5") or subs["hash"]
                )

        # Resolve endpoint template
        try:
            endpoint = endpoint_template.format(**subs)
        except KeyError as e:
            return None, f"missing placeholder {e}"

        full_url = api_url.rstrip("/") + endpoint

        # Make the API request with explicit timeout
        response = session.get(
            full_url, headers=headers, verify=verify_ssl, timeout=effective_timeout
        )

        if response.ok:
            try:
                result = response.json()
            except ValueError:
                return None, "invalid JSON response"

            # Unwrap common response wrappers
            if isinstance(result, dict):
                if "rl" in result:
                    result = result["rl"]
                if "results" in result and isinstance(result.get("results"), list):
                    return {"_items": result["results"]}, None
                if "extracted_files" in result:
                    return {"_items": result["extracted_files"]}, None
                if "downloaded_files" in result:
                    return {"_items": result["downloaded_files"]}, None
            return result, None

        # HTTP error
        return None, f"HTTP {response.status_code}"

    except requests.exceptions.Timeout:
        return None, f"timeout after {effective_timeout}s"
    except requests.exceptions.ConnectionError:
        return None, "connection error"
    except requests.exceptions.RequestException as e:
        return None, f"request error: {type(e).__name__}"
    except Exception as e:
        # Catch-all for unexpected errors
        return None, f"unexpected error: {type(e).__name__}"


def _process_object_recursive(
    obj_key: str,
    obj_def: Dict,
    data: Dict,
    original_value: str,
    results: Dict,
    created_objects: Dict,
    parent_obj: Optional[Dict] = None,
    api_context: Optional[Dict] = None,
) -> Optional[Dict]:
    """Recursively process an object definition and its nested children.

    Args:
        obj_key: Object key (may include relationship notation)
        obj_def: Object definition dict
        data: API response data
        original_value: Original IOC value
        results: Results container to append to
        created_objects: Dict tracking created objects by name
        parent_obj: Parent object to link to (if any)
        api_context: Optional API context for nested endpoint calls

    Returns:
        Created object dict (or None if no attributes)
    """
    obj_name, rels, array_path, filter_expr, obj_limit = _parse_obj_key(obj_key)

    # NOTE: We do NOT inherit parent_default_rels here.
    # Parent relationships (like "analysed-with: report") are about the parent,
    # not the child. Inheriting them causes children to create wrong/circular refs.
    # Children must define their own obj:<rel>-> directives if needed.

    # Separate attributes from nested objects
    attr_def = {}
    nested_objects = []
    obj_comment = ""

    for key, value in obj_def.items():
        if (
            re.match(r"^obj:fetch(\[\d+\])?$", key)
            and isinstance(value, dict)
            and value.get("obj:uri")
        ):
            # obj:fetch (or obj:fetch[N]) with dict value is a nested endpoint call
            nested_objects.append((key, value))
        elif key.startswith("obj:"):
            # obj: directives, keep in attr_def for obj:type lookup
            attr_def[key] = value
        elif key.startswith("_") and "[]" not in key:
            # Other _ prefixed keys (but not foreach like _items[])
            attr_def[key] = value
        elif key == "{{#Comment}}" or key.lower() == "{{#comment}}":
            # Object-level MISP comment
            obj_comment = _resolve_dsl_in_comment(str(value), data, api_context)
        elif _is_nested_object(key, value):
            nested_objects.append((key, value))
        else:
            attr_def[key] = value

    # Parse obj-level relationship directives of the form
    #   "obj:contains->": ["file","report"]  or "file" or "*"
    # Merge these with any relationships parsed from the key brackets.
    rels_from_attr: list = []
    for dkey, dval in list(attr_def.items()):
        if dkey.startswith("obj:") and "->" in dkey:
            # Expect format obj:<rel>->
            m = re.match(r"^obj:([\w\-]+)->$", dkey)
            if m:
                rel_type = m.group(1)
                targets = []
                if dval == "*":
                    targets = ["*"]
                elif isinstance(dval, list):
                    targets = [str(x) for x in dval if x]
                elif isinstance(dval, str) and dval:
                    # allow comma-separated
                    if "," in dval:
                        targets = [t.strip() for t in dval.split(",") if t.strip()]
                    else:
                        targets = [dval.strip()]
                else:
                    targets = []
                rels_from_attr.append({"type": rel_type, "targets": targets})

    if rels_from_attr:
        # merge preserving existing rels order
        rels = rels + rels_from_attr if isinstance(rels, list) else rels_from_attr

    # Apply default relationships from constants if no relationships defined
    if not rels and obj_name in OBJECT_RELATIONSHIPS:
        default_rels = OBJECT_RELATIONSHIPS[obj_name]
        rels = [
            {"type": rel_type, "targets": [target]} for target, rel_type in default_rels.items()
        ]

    # Build attributes for this object
    attributes = _build_attributes_from_def(
        data, attr_def, original_value, results, api_context=api_context
    )

    obj = None
    if attributes:
        obj_type = obj_def.get("obj:type", obj_name)
        # obj:comment directive overrides {{#Comment}} key
        raw_obj_comment = obj_def.get("obj:comment", obj_comment)
        obj_comment = (
            _resolve_dsl_in_comment(raw_obj_comment, data, api_context)
            if raw_obj_comment
            else obj_comment
        )
        new_obj = create_misp_object(obj_type, attributes, comment=obj_comment)
        # Apply deterministic UUIDs for key object types to support reuse
        det_uuid = _compute_deterministic_uuid(
            obj_type,
            attributes,
            original_value,
            api_context.get("ioc_type") if api_context else None,
        )
        if det_uuid:
            new_obj["uuid"] = det_uuid
            # If object with same UUID exists, merge attributes and reuse
            existing_obj = next(
                (o for o in results.get("Object", []) if o.get("uuid") == det_uuid), None
            )
            if existing_obj:
                existing_attrs = existing_obj.get("Attribute", [])
                seen_pairs = {
                    (str(a.get("object_relation", "")).lower(), str(a.get("value")))
                    for a in existing_attrs
                }
                for a in new_obj.get("Attribute", []):
                    key = (str(a.get("object_relation", "")).lower(), str(a.get("value")))
                    if key not in seen_pairs:
                        existing_attrs.append(a)
                        seen_pairs.add(key)
                existing_obj["Attribute"] = existing_attrs
                obj = existing_obj
            else:
                results["Object"].append(new_obj)
                obj = new_obj
        else:
            results["Object"].append(new_obj)
            obj = new_obj
        # Store created objects in a list (multiple objects may share the same name)
        if obj_name not in created_objects:
            created_objects[obj_name] = []
        created_objects[obj_name].append(obj)

        # Create reference from this object to parent if obj:<rel>-> targets parent type
        # This handles "obj:contained-within->": ["file"] style relationships
        if parent_obj and rels:
            parent_type = parent_obj.get("name", "")
            for rel in rels:
                rel_targets = rel.get("targets", [])
                # Check if this relationship targets the parent
                if parent_type in rel_targets or "*" in rel_targets:
                    relationship = rel["type"].replace("-", "_")
                    ref = create_object_reference(obj["uuid"], parent_obj["uuid"], relationship)
                    if "ObjectReference" not in obj:
                        obj["ObjectReference"] = []
                    obj["ObjectReference"].append(ref)

    # Process nested children and collect them
    child_objects = []
    for child_key, child_def in nested_objects:
        # Support dict-form handler declaration: child_def may be a dict containing an
        # 'obj:handler' key, e.g. { "obj:handler": "iterate_dns last_dns_records A,AAAA" }
        if isinstance(child_def, dict) and "obj:handler" in child_def:
            handler_str = child_def.get("obj:handler")
            if handler_str and isinstance(handler_str, str):
                # Allow both bare handler strings ("iterate_dns ...") and templated form ("{{#iterate_dns ...}}")
                if handler_str.startswith("{{#"):
                    handler_match = re.match(r"\{\{#(\w+)(?:\s+(.+?))?\}\}", handler_str)
                else:
                    handler_match = re.match(r"(\w+)(?:\s+(.+?))?$", handler_str)

                if handler_match:
                    handler_name = handler_match.group(1)
                    handler_path = (handler_match.group(2) or "").strip()
                    if handler_name == "iterate_dns":
                        parts = handler_path.split(None, 1) if handler_path else []
                        if len(parts) >= 1:
                            records_path = parts[0]
                            type_filter = parts[1].split(",") if len(parts) > 1 else []
                            type_filter = [t.strip().upper() for t in type_filter]

                            records = get_first(data, [records_path])
                            if records and isinstance(records, list):
                                child_obj_name, child_rels, _, _, _ = _parse_obj_key(child_key)
                                seen_values: Set[str] = set()
                                created_children = 0
                                truncated_tag_emitted = False

                                for record in records:
                                    if not isinstance(record, dict):
                                        continue
                                    record_type = str(record.get("type", "")).upper()
                                    if type_filter and record_type not in type_filter:
                                        continue
                                    record_value = record.get("value")
                                    if not record_value:
                                        continue

                                    if record_type == "TXT":
                                        spf_endpoints = _parse_spf_for_endpoints(str(record_value))
                                        for ptype, pval in spf_endpoints:
                                            if pval.lower() in seen_values:
                                                continue
                                            seen_values.add(pval.lower())
                                            attrs = []
                                            if ptype == "ip":
                                                attrs.append(
                                                    create_misp_attribute(
                                                        misp_type="ip",
                                                        value=pval,
                                                        object_relation="ip",
                                                    )
                                                )
                                            elif ptype == "domain":
                                                attrs.append(
                                                    create_misp_attribute(
                                                        misp_type="hostname",
                                                        value=pval,
                                                        object_relation="hostname",
                                                    )
                                                )

                                            created_children, truncated_tag_emitted, child_obj = (
                                                _add_child_object_with_limit(
                                                    child_obj_name=child_obj_name,
                                                    child_key=child_key,
                                                    attrs=attrs,
                                                    child_objects=child_objects,
                                                    results=results,
                                                    created_children=created_children,
                                                    limit=MAX_DNS_CHILDREN,
                                                    truncated_tag_emitted=truncated_tag_emitted,
                                                    note_label="dns children",
                                                    original_value=original_value,
                                                    ioc_type=api_context.get("ioc_type")
                                                    if api_context
                                                    else None,
                                                )
                                            )
                                        continue

                                    if str(record_value).lower() in seen_values:
                                        continue
                                    seen_values.add(str(record_value).lower())

                                    attrs = []
                                    if record_type in ("A", "AAAA"):
                                        attrs.append(
                                            create_misp_attribute(
                                                misp_type="ip",
                                                value=record_value,
                                                object_relation="ip",
                                            )
                                        )
                                    elif record_type in ("NS", "CNAME", "MX", "PTR"):
                                        attrs.append(
                                            create_misp_attribute(
                                                misp_type="hostname",
                                                value=record_value,
                                                object_relation="hostname",
                                            )
                                        )

                                    created_children, truncated_tag_emitted, child_obj = (
                                        _add_child_object_with_limit(
                                            child_obj_name=child_obj_name,
                                            child_key=child_key,
                                            attrs=attrs,
                                            child_objects=child_objects,
                                            results=results,
                                            created_children=created_children,
                                            limit=MAX_DNS_CHILDREN,
                                            truncated_tag_emitted=truncated_tag_emitted,
                                            note_label="dns children",
                                            original_value=original_value,
                                            ioc_type=api_context.get("ioc_type")
                                            if api_context
                                            else None,
                                        )
                                    )
                    elif handler_name == "extract_iocs":
                        # extract_iocs <records_path> <types>
                        # types: comma-separated list of 'ip' and/or 'domain'
                        parts = handler_path.split(None, 1) if handler_path else []
                        if len(parts) >= 1:
                            records_path = parts[0]
                            types = []
                            if len(parts) > 1:
                                types = [
                                    t.strip().lower() for t in parts[1].split(",") if t.strip()
                                ]
                            if not types:
                                types = ["ip", "domain"]

                            records = get_first(data, [records_path])
                            if records is None:
                                # try single value
                                records = get_first(data, [records_path])
                            items = records if isinstance(records, list) else [records]
                            child_obj_name, child_rels, _, _, _ = _parse_obj_key(child_key)
                            seen_values: Set[str] = set()
                            created_children = 0
                            truncated_tag_emitted = False

                            # simple regexes for IPv4 and hostname-like domains
                            ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
                            host_re = re.compile(
                                r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b"
                            )

                            for it in items:
                                if it is None:
                                    continue
                                if isinstance(it, dict):
                                    val = it.get("value") or it.get("name") or str(it)
                                else:
                                    val = str(it)
                                # search for IPs
                                if "ip" in types:
                                    for m in ipv4_re.finditer(val):
                                        ioc = m.group(0)
                                        if ioc.lower() in seen_values:
                                            continue
                                        seen_values.add(ioc.lower())
                                        if created_children >= MAX_DNS_CHILDREN:
                                            if not truncated_tag_emitted:
                                                try:
                                                    results["Tag"].append(
                                                        create_tag(
                                                            "rl",
                                                            "note",
                                                            f"dns children truncated after {MAX_DNS_CHILDREN} items",
                                                        )
                                                    )
                                                except Exception:
                                                    pass
                                                truncated_tag_emitted = True
                                            continue
                                        attrs = [
                                            create_misp_attribute(
                                                misp_type="ip", value=ioc, object_relation="ip"
                                            )
                                        ]
                                        child_obj = create_misp_object(child_obj_name, attrs)
                                        det_uuid = _compute_deterministic_uuid(
                                            child_obj_name,
                                            attrs,
                                            original_value,
                                            api_context.get("ioc_type") if api_context else None,
                                        )
                                        if det_uuid:
                                            child_obj["uuid"] = det_uuid
                                            existing_obj = next(
                                                (
                                                    o
                                                    for o in results.get("Object", [])
                                                    if o.get("uuid") == det_uuid
                                                ),
                                                None,
                                            )
                                            if existing_obj:
                                                existing_attrs = existing_obj.get("Attribute", [])
                                                seen_pairs = {
                                                    (
                                                        str(a.get("object_relation", "")).lower(),
                                                        str(a.get("value")),
                                                    )
                                                    for a in existing_attrs
                                                }
                                                for a in child_obj.get("Attribute", []):
                                                    key = (
                                                        str(a.get("object_relation", "")).lower(),
                                                        str(a.get("value")),
                                                    )
                                                    if key not in seen_pairs:
                                                        existing_attrs.append(a)
                                                        seen_pairs.add(key)
                                                existing_obj["Attribute"] = existing_attrs
                                                child_objects.append((child_key, existing_obj))
                                                created_children += 1
                                                continue
                                        results["Object"].append(child_obj)
                                        child_objects.append((child_key, child_obj))
                                        created_children += 1
                                # search for hostnames/domains
                                if "domain" in types:
                                    for m in host_re.finditer(val):
                                        ioc = m.group(0)
                                        # skip pure numeric matches (avoid matching IPs again)
                                        if ipv4_re.fullmatch(ioc):
                                            continue
                                        if ioc.lower() in seen_values:
                                            continue
                                        seen_values.add(ioc.lower())
                                        if created_children >= MAX_DNS_CHILDREN:
                                            if not truncated_tag_emitted:
                                                try:
                                                    results["Tag"].append(
                                                        create_tag(
                                                            "rl",
                                                            "note",
                                                            f"dns children truncated after {MAX_DNS_CHILDREN} items",
                                                        )
                                                    )
                                                except Exception:
                                                    pass
                                                truncated_tag_emitted = True
                                            continue
                                        attrs = [
                                            create_misp_attribute(
                                                misp_type="hostname",
                                                value=ioc,
                                                object_relation="hostname",
                                            )
                                        ]
                                        child_obj = create_misp_object(child_obj_name, attrs)
                                        det_uuid = _compute_deterministic_uuid(
                                            child_obj_name,
                                            attrs,
                                            original_value,
                                            api_context.get("ioc_type") if api_context else None,
                                        )
                                        if det_uuid:
                                            child_obj["uuid"] = det_uuid
                                            existing_obj = next(
                                                (
                                                    o
                                                    for o in results.get("Object", [])
                                                    if o.get("uuid") == det_uuid
                                                ),
                                                None,
                                            )
                                            if existing_obj:
                                                existing_attrs = existing_obj.get("Attribute", [])
                                                seen_pairs = {
                                                    (
                                                        str(a.get("object_relation", "")).lower(),
                                                        str(a.get("value")),
                                                    )
                                                    for a in existing_attrs
                                                }
                                                for a in child_obj.get("Attribute", []):
                                                    key = (
                                                        str(a.get("object_relation", "")).lower(),
                                                        str(a.get("value")),
                                                    )
                                                    if key not in seen_pairs:
                                                        existing_attrs.append(a)
                                                        seen_pairs.add(key)
                                                existing_obj["Attribute"] = existing_attrs
                                                child_objects.append((child_key, existing_obj))
                                                created_children += 1
                                                continue
                                        results["Object"].append(child_obj)
                                        child_objects.append((child_key, child_obj))
                                        created_children += 1
            continue

        # Handle obj:fetch dict syntax: fetch from URI and iterate over objects template
        # Supports obj:fetch, obj:fetch[0], obj:fetch[1], etc.
        if (
            re.match(r"^obj:fetch(\[\d+\])?$", child_key)
            and isinstance(child_def, dict)
            and child_def.get("obj:uri")
        ):
            if api_context:
                uri = child_def["obj:uri"]
                # Get optional per-endpoint timeout from mapping (e.g., "obj:timeout": 60)
                endpoint_timeout = child_def.get("obj:timeout")
                if endpoint_timeout is not None:
                    try:
                        endpoint_timeout = int(endpoint_timeout)
                    except (ValueError, TypeError):
                        endpoint_timeout = None

                endpoint_data, endpoint_error = _fetch_object_endpoint(
                    uri, data, original_value, api_context, timeout=endpoint_timeout
                )

                # On failure, emit a tag so user knows enrichment was partial
                if endpoint_error:
                    try:
                        # Shorten URI for tag (just the path, not full URL)
                        short_uri = uri.split("/")[-2] if uri.endswith("/") else uri.split("/")[-1]
                        results["Tag"].append(
                            create_tag("rl", "fetch-error", f"{short_uri}: {endpoint_error}")
                        )
                    except Exception:
                        pass

                if endpoint_data:
                    # Find the objects template (key ending with [])
                    obj_template_key = None
                    obj_template_def = None
                    for k, v in child_def.items():
                        if k.endswith("[]") and isinstance(v, dict):
                            obj_template_key = k
                            obj_template_def = v
                            break

                    if obj_template_key and obj_template_def:
                        # Get the array data (usually _items from _fetch_object_endpoint)
                        array_path = obj_template_key.rstrip("[]").lstrip("_")
                        items = endpoint_data.get("_items") or endpoint_data.get(array_path) or []
                        if isinstance(items, list):
                            seen_values: Set[str] = set()
                            created_children = 0
                            truncated_tag_emitted = False

                            for item in items:
                                if not isinstance(item, dict):
                                    continue

                                # Deduplicate by sha256 or first value (check nested sample too)
                                dedup_key = (
                                    item.get("sha256") or item.get("sha1") or item.get("md5")
                                )
                                if not dedup_key:
                                    # Check nested sample object (common in A1000 responses)
                                    sample = item.get("sample", {})
                                    if isinstance(sample, dict):
                                        dedup_key = (
                                            sample.get("sha256")
                                            or sample.get("sha1")
                                            or sample.get("md5")
                                        )
                                if not dedup_key:
                                    for v in item.values():
                                        if v is not None and not isinstance(v, (dict, list)):
                                            dedup_key = str(v).lower()
                                            break

                                if dedup_key and str(dedup_key).lower() in seen_values:
                                    continue
                                if dedup_key:
                                    seen_values.add(str(dedup_key).lower())

                                # Truncate if too many
                                if created_children >= MAX_DNS_CHILDREN:
                                    if not truncated_tag_emitted:
                                        try:
                                            obj_type = obj_template_def.get("obj:type", "file")
                                            results["Tag"].append(
                                                create_tag(
                                                    "rl",
                                                    "note",
                                                    f"{obj_type} children truncated after {MAX_DNS_CHILDREN} items",
                                                )
                                            )
                                        except Exception:
                                            pass
                                        truncated_tag_emitted = True
                                    continue

                                # Process item with the object template
                                child_obj = _process_object_recursive(
                                    obj_template_key,
                                    obj_template_def,
                                    item,  # Item as data context
                                    original_value,
                                    results,
                                    created_objects,
                                    parent_obj=obj,
                                    api_context=api_context,
                                )
                                if child_obj:
                                    child_objects.append((obj_template_key, child_obj))
                                    created_children += 1
            continue

        # Regular dict-based nested object (child_def is guaranteed to be dict here)
        if not isinstance(child_def, dict):
            continue

        # Check for obj:path directive - consistent directive-based foreach syntax
        # Example: "dns-ips": { "obj:type": "ip-port", "obj:path": "last_dns_records[type=A,AAAA]", ... }
        obj_path_value = child_def.get("obj:path")
        if obj_path_value:
            # Parse the obj:path value to extract path and optional filter
            # Supports: "array_path", "array_path[]", "array_path[filter]", "array_path[100]"
            _, _, foreach_path, foreach_filter, foreach_limit = _parse_obj_key(obj_path_value)

            # If no path was parsed (no [] syntax), treat the whole value as the path
            if not foreach_path:
                foreach_path = obj_path_value.strip()

            # Get the data at the path
            path_data = get_first(data, [foreach_path])

            if path_data is not None:
                # Auto-detect: if it's a list, iterate; if it's a dict, treat as single item
                if isinstance(path_data, list):
                    # Array iteration
                    seen_values: Set[str] = set()
                    created_children = 0
                    truncated_tag_emitted = False

                    for item in path_data:
                        if not isinstance(item, dict):
                            continue

                        # Apply filter if present
                        if foreach_filter and not _matches_filter(item, foreach_filter):
                            continue

                        # Deduplicate by a hash of key values (or first string value)
                        dedup_key = None
                        if "value" in item:
                            dedup_key = str(item["value"]).lower()
                        elif item:
                            # Use first non-None value as dedup key
                            for v in item.values():
                                if v is not None:
                                    dedup_key = str(v).lower()
                                    break

                        if dedup_key and dedup_key in seen_values:
                            continue
                        if dedup_key:
                            seen_values.add(dedup_key)

                        # Truncate if too many children (use parsed limit, fallback to default)
                        effective_limit = (
                            foreach_limit
                            if foreach_limit != MAX_FOREACH_ITERATIONS
                            else MAX_DNS_CHILDREN
                        )
                        if created_children >= effective_limit:
                            if not truncated_tag_emitted:
                                try:
                                    obj_type = child_def.get("obj:type", foreach_path)
                                    results["Tag"].append(
                                        create_tag(
                                            "rl",
                                            "note",
                                            f"{obj_type} children truncated after {effective_limit} items",
                                        )
                                    )
                                except Exception:
                                    pass
                                truncated_tag_emitted = True
                            continue

                        # Process this item with the object definition, using item as scoped data
                        child_obj = _process_object_recursive(
                            child_key,
                            child_def,
                            {
                                **data,
                                **item,
                            },  # Merge parent context with item (item overrides parent)
                            original_value,
                            results,
                            created_objects,
                            parent_obj=obj,
                            api_context=api_context,
                        )
                        if child_obj:
                            child_objects.append((child_key, child_obj))
                            created_children += 1
                elif isinstance(path_data, dict):
                    # Single object - process as one item
                    child_obj = _process_object_recursive(
                        child_key,
                        child_def,
                        {**data, **path_data},  # Merge parent context with path data
                        original_value,
                        results,
                        created_objects,
                        parent_obj=obj,
                        api_context=api_context,
                    )
                    if child_obj:
                        child_objects.append((child_key, child_obj))
                continue

        # Check for foreach syntax: "array_path[]" or "array_path[filter][]" or "array_path[100]"
        _, _, foreach_path, foreach_filter, foreach_limit = _parse_obj_key(child_key)

        if foreach_path:
            # Foreach iteration: create multiple objects from array
            array_data = get_first(data, [foreach_path])
            if array_data and isinstance(array_data, list):
                seen_values: Set[str] = set()
                created_children = 0
                truncated_tag_emitted = False

                for item in array_data:
                    if not isinstance(item, dict):
                        continue

                    # Apply filter if present
                    if foreach_filter and not _matches_filter(item, foreach_filter):
                        continue

                    # Deduplicate by a hash of key values (or first string value)
                    dedup_key = None
                    if "value" in item:
                        dedup_key = str(item["value"]).lower()
                    elif item:
                        # Use first non-None value as dedup key
                        for v in item.values():
                            if v is not None:
                                dedup_key = str(v).lower()
                                break

                    if dedup_key and dedup_key in seen_values:
                        continue
                    if dedup_key:
                        seen_values.add(dedup_key)

                    # Truncate if too many children (use parsed limit, fallback to default)
                    effective_limit = (
                        foreach_limit
                        if foreach_limit != MAX_FOREACH_ITERATIONS
                        else MAX_DNS_CHILDREN
                    )
                    if created_children >= effective_limit:
                        if not truncated_tag_emitted:
                            try:
                                obj_type = child_def.get("obj:type", foreach_path)
                                results["Tag"].append(
                                    create_tag(
                                        "rl",
                                        "note",
                                        f"{obj_type} children truncated after {effective_limit} items",
                                    )
                                )
                            except Exception:
                                pass
                            truncated_tag_emitted = True
                        continue

                    # Process this item with the object definition, using item as scoped data
                    child_obj = _process_object_recursive(
                        child_key,
                        child_def,
                        {**data, **item},  # Merge parent context with item (item overrides parent)
                        original_value,
                        results,
                        created_objects,
                        parent_obj=obj,
                        api_context=api_context,
                    )
                    if child_obj:
                        child_objects.append((child_key, child_obj))
                        created_children += 1
            continue

        # Standard single object processing
        child_obj = _process_object_recursive(
            child_key,
            child_def,
            data,
            original_value,
            results,
            created_objects,
            parent_obj=obj,  # This object becomes the parent for context
            api_context=api_context,
        )
        if child_obj:
            child_objects.append((child_key, child_obj))

    # For any relationship entries that have no explicit targets, link this object
    # to all nested children using the relationship type.
    if obj and rels and child_objects:
        for rel in rels:
            if not rel.get("targets"):
                relationship = rel["type"].replace("-", "_")
                for _child_key, child_obj in child_objects:
                    ref = create_object_reference(obj["uuid"], child_obj["uuid"], relationship)
                    if "ObjectReference" not in obj:
                        obj["ObjectReference"] = []
                    obj["ObjectReference"].append(ref)

    # Apply dynamic relationships for specific child object types
    if obj and child_objects:
        obj_type = obj.get("name", obj_name)
        if obj_type in DYNAMIC_RELATIONSHIPS:
            dynamic_rels = DYNAMIC_RELATIONSHIPS[obj_type]
            for child_key, child_obj in child_objects:
                child_type = child_obj.get("name", child_key.split("[")[0])
                if child_type in dynamic_rels:
                    relationship = dynamic_rels[child_type].replace("-", "_")
                    ref = create_object_reference(obj["uuid"], child_obj["uuid"], relationship)
                    if "ObjectReference" not in obj:
                        obj["ObjectReference"] = []
                    obj["ObjectReference"].append(ref)

    # If THIS object has relationship entries with explicit targets, store for later resolution
    if obj and rels:
        for rel in rels:
            targets = rel.get("targets", [])
            if targets:
                if "_pending_refs" not in results:
                    results["_pending_refs"] = []
                for target in targets:
                    # Skip self-references (don't link object to itself)
                    if target == obj_name or target == obj.get("name"):
                        continue
                    results["_pending_refs"].append(
                        {
                            "source_obj": obj,
                            "source_name": obj_name,
                            "target_name": target,
                            "relationship": rel["type"].replace("-", "_"),
                        }
                    )

    return obj


def apply_mappings(
    data: Dict,
    mappings: Dict,
    ioc_type: str,
    original_value: str,
    api_context: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Apply declarative mappings to API response with hierarchical object creation.

    Supports nested object definitions where nesting defines the hierarchy.
    Relationships are defined using obj:<rel>-> directives:

        "domain-ip": {
            "obj:related-to->": ["report"],
            "domain": "{{#ref requested_domain}}",
            "report": {
                "obj:related-to->": ["dns-record"],
                "title": "Report",
                "dns-record": {
                    "queried-domain": "{{#ref domain}}"
                }
            }
        }

    Args:
        data: API response data
        mappings: Full mappings dictionary
        ioc_type: IOC type being enriched
        original_value: Original IOC value (for fallbacks)
        api_context: Optional API context for nested endpoint calls (session, headers, etc.)

    Returns:
        MISP results with Object, Attribute, Tag lists
    """
    results = build_results_container()

    # Get IOC-specific mappings (comments already stripped)
    ioc_mappings = get_ioc_mappings(mappings, ioc_type)

    # Track created objects by name for relationship building
    created_objects: Dict[str, Dict] = {}

    # Process top-level entries - dict values become objects, string values become event-level attributes
    for obj_key, obj_def in ioc_mappings.items():
        if obj_key.startswith("_"):
            continue

        if isinstance(obj_def, str):
            # String value at top level = event-level attribute
            _process_event_level_attribute(
                obj_key,
                obj_def,
                data,
                original_value,
                results,
                api_context=api_context,
            )
        elif isinstance(obj_def, dict):
            # Check for foreach syntax at top level
            _, _, foreach_path, foreach_filter, foreach_limit = _parse_obj_key(obj_key)

            if foreach_path:
                # Top-level foreach iteration
                array_data = get_first(data, [foreach_path])
                if array_data and isinstance(array_data, list):
                    seen_values: Set[str] = set()
                    created_children = 0
                    truncated_tag_emitted = False

                    for item in array_data:
                        if not isinstance(item, dict):
                            continue

                        # Apply filter if present
                        if foreach_filter and not _matches_filter(item, foreach_filter):
                            continue

                        # Deduplicate by value field
                        dedup_key = None
                        if "value" in item:
                            dedup_key = str(item["value"]).lower()
                        elif item:
                            for v in item.values():
                                if v is not None:
                                    dedup_key = str(v).lower()
                                    break

                        if dedup_key and dedup_key in seen_values:
                            continue
                        if dedup_key:
                            seen_values.add(dedup_key)

                        # Truncate if too many (use parsed limit, fallback to default)
                        effective_limit = (
                            foreach_limit
                            if foreach_limit != MAX_FOREACH_ITERATIONS
                            else MAX_DNS_CHILDREN
                        )
                        if created_children >= effective_limit:
                            if not truncated_tag_emitted:
                                try:
                                    obj_type = obj_def.get("obj:type", foreach_path)
                                    results["Tag"].append(
                                        create_tag(
                                            "rl",
                                            "note",
                                            f"{obj_type} truncated after {effective_limit} items",
                                        )
                                    )
                                except Exception:
                                    pass
                                truncated_tag_emitted = True
                            continue

                        # Process with item as scoped data
                        child_obj = _process_object_recursive(
                            obj_key,
                            obj_def,
                            item,
                            original_value,
                            results,
                            created_objects,
                            parent_obj=None,
                            api_context=api_context,
                        )
                        if child_obj:
                            created_children += 1
            else:
                # Dict value = object definition (existing behavior)
                _process_object_recursive(
                    obj_key,
                    obj_def,
                    data,
                    original_value,
                    results,
                    created_objects,
                    parent_obj=None,
                    api_context=api_context,
                )

    # Resolve pending references to sibling objects
    if "_pending_refs" in results:
        for pending in results["_pending_refs"]:
            target_name = pending["target_name"]
            if target_name in created_objects:
                target_objs = created_objects[target_name]
                # Support both single object (legacy) and list of objects
                if not isinstance(target_objs, list):
                    target_objs = [target_objs]
                source_obj = pending["source_obj"]
                for target_obj in target_objs:
                    # Skip self-references (same UUID)
                    if source_obj["uuid"] == target_obj["uuid"]:
                        continue
                    ref = create_object_reference(
                        source_obj["uuid"], target_obj["uuid"], pending["relationship"]
                    )
                    if "ObjectReference" not in source_obj:
                        source_obj["ObjectReference"] = []
                    # Check for duplicate before adding
                    existing = {
                        (r.get("referenced_uuid"), r.get("relationship_type"))
                        for r in source_obj["ObjectReference"]
                    }
                    if (ref["referenced_uuid"], ref["relationship_type"]) not in existing:
                        source_obj["ObjectReference"].append(ref)
        del results["_pending_refs"]

    # Deduplicate ObjectReferences in all objects
    for obj in results.get("Object", []):
        if "ObjectReference" in obj:
            seen = set()
            deduped = []
            for ref in obj["ObjectReference"]:
                key = (ref.get("referenced_uuid"), ref.get("relationship_type"))
                if key not in seen:
                    seen.add(key)
                    deduped.append(ref)
            obj["ObjectReference"] = deduped

    # Final deduplication: remove duplicate objects by UUID (keep first occurrence)
    seen_uuids: Set[str] = set()
    deduped_objects: List[Dict] = []
    for obj in results.get("Object", []):
        obj_uuid = obj.get("uuid")
        if obj_uuid and obj_uuid in seen_uuids:
            continue  # Skip duplicate
        if obj_uuid:
            seen_uuids.add(obj_uuid)
        deduped_objects.append(obj)
    results["Object"] = deduped_objects

    # Deduplicate attributes inside objects to avoid repeated values
    results = _deduplicate_object_attributes(results)

    # Deduplicate tags before returning
    results = _deduplicate_tags(results)

    # Collect all ObjectReferences from objects into top-level ObjectReference list
    # MISP requires references at the top level for proper persistence
    seen_refs: Set[Tuple[str, str, str]] = set()  # (source_uuid, target_uuid, rel_type)
    for obj in results.get("Object", []):
        for ref in obj.get("ObjectReference", []):
            ref_key = (
                ref.get("object_uuid", ""),
                ref.get("referenced_uuid", ""),
                ref.get("relationship_type", ""),
            )
            if ref_key not in seen_refs:
                seen_refs.add(ref_key)
                results["ObjectReference"].append(ref)

    return results


def _process_event_level_attribute(
    attr_name: str,
    attr_def: str,
    data: Dict,
    original_value: str,
    results: Dict,
    api_context: Optional[Dict] = None,
) -> None:
    """Process a top-level string value as an event-level attribute.

    Event-level attributes are defined as string values (not dicts) at the
    top level of an IOC mapping. This allows adding standalone attributes
    directly to the MISP event without wrapping them in objects.

    Example mapping:
        "file": {
            "file": { "obj:type": "file", ... },   # Creates object
            "sha256": "{{#ref sample_summary.sha256}}"  # Creates event-level attribute
        }

    Args:
        attr_name: Attribute relation name (e.g., 'sha256', 'domain')
        attr_def: DSL string defining the attribute value
        data: API response data
        original_value: Original IOC value for fallbacks
        results: Results container to append attribute to
    """
    # Parse the DSL string
    field_def = _parse_dsl(attr_def)

    handler_name = field_def.get("handler")
    handler_path = field_def.get("handler_path", "")
    value = None

    if handler_name == "ref":
        # {{#ref path}} - extracts value from API response
        paths = [handler_path] if handler_path else []
        if paths and "|" in paths[0]:
            tokens = [p.strip() for p in paths[0].split("|")]
        else:
            tokens = paths
        value = _resolve_ref_with_literals(data, tokens) if tokens else None
    elif handler_name == "if":
        # Block conditional handled here. handler_path contains the condition tokens.
        cond_raw = handler_path or ""
        cond_tokens = [p.strip() for p in cond_raw.split("|")] if cond_raw else []
        cond_val = _resolve_ref_with_literals(data, cond_tokens) if cond_tokens else None
        cond_truth = bool(cond_val)

        # Select appropriate block
        true_block = field_def.get("true_block", "")
        false_block = field_def.get("false_block")
        selected = true_block if cond_truth else false_block

        # If no selected block, treat as missing
        if selected is None:
            return

        # Parse selected block as a mini-DSL and evaluate (support simple ref or literal)
        sel_def = _parse_dsl(selected)
        # Simple nested ref handling
        if sel_def.get("handler") == "ref":
            p = sel_def.get("handler_path", "")
            tokens = [t.strip() for t in p.split("|")] if "|" in p else ([p] if p else [])
            value = _resolve_ref_with_literals(data, tokens) if tokens else None
        elif "value" in sel_def:
            value = sel_def["value"]
        elif "paths" in sel_def:
            value = get_first(data, sel_def["paths"])
        else:
            value = None
    elif handler_name == "summary":
        # {{#summary}} - unified summary handler
        value = _build_unified_summary(data, api_context)
    elif handler_name == "build_link":
        # {{#build_link ioc_type}} - construct link using configuration
        ioc_type = handler_path.strip() if handler_path else ""
        type_config = IOC_TYPE_CONFIG.get(ioc_type, {}) if ioc_type else {}
        value_fields = type_config.get("value_fields", [])

        ioc_value = get_first(data, value_fields) if value_fields else None
        if ioc_value:
            link_template = type_config.get("link_template")
            if link_template:
                # Ensure api_url is always provided to the template (use env or fallback)
                fmt_kwargs = {"value": ioc_value}
                base = None
                if api_context and isinstance(api_context.get("api_url"), str):
                    base = api_context.get("api_url")
                else:
                    base = os.getenv("RL_API_URL")
                if not base:
                    base = "https://a1000.reversinglabs.com"
                fmt_kwargs["api_url"] = (base).rstrip("/")
                value = link_template.format(**fmt_kwargs)
            elif ioc_type == "url":
                # URL needs special encoding
                base = None
                if api_context and isinstance(api_context.get("api_url"), str):
                    base = api_context.get("api_url")
                else:
                    base = os.getenv("RL_API_URL")
                if not base:
                    base = "https://a1000.reversinglabs.com"
                base = (base).rstrip("/")
                value = f"{base}/url/{quote(ioc_value, safe='')}/analysis/url/"
            else:
                # Fallback for unknown types
                base = None
                if api_context and isinstance(api_context.get("api_url"), str):
                    base = api_context.get("api_url")
                else:
                    base = os.getenv("RL_API_URL")
                base = (base).rstrip("/")
                value = f"{base}/{ioc_type}/{ioc_value}/"
    elif handler_name is None:
        # No handler - try paths or static value
        paths = field_def.get("paths", [])
        if paths:
            value = get_first(data, paths)
        elif "value" in field_def:
            value = field_def["value"]

    # Treat trimmed-empty string as missing
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return
    if value is None:
        return

    # Determine MISP type from the attribute name or value
    misp_type = _infer_misp_type_from_name(attr_name) or _determine_misp_type(value)

    # Create event-level attribute (no object_relation for standalone attributes)
    # MISP requires uuid for attributes to persist
    attr_comment = field_def.get("comment", "")
    if attr_comment:
        attr_comment = _resolve_dsl_in_comment(attr_comment, data, api_context)
    # Priority: explicit type hint in DSL > inferred from field name > determined from value
    event_misp_type = (
        field_def.get("type_hint") or _infer_misp_type_from_name(attr_name) or misp_type
    )
    attr = {
        "uuid": str(uuid.uuid4()),
        "type": event_misp_type,
        "value": value,
        "category": _infer_category_from_type(event_misp_type),
        "to_ids": _should_be_ids(event_misp_type),
        "disable_correlation": False,
    }
    if attr_comment:
        attr["comment"] = attr_comment

    results["Attribute"].append(attr)


def _infer_misp_type_from_name(name: str) -> Optional[str]:
    """Infer MISP attribute type from the field name.

    Args:
        name: Field name (e.g., 'sha256', 'ip-dst', 'domain')

    Returns:
        MISP type string or None if cannot be inferred
    """
    # Common hash types
    hash_types = {"md5", "sha1", "sha256", "sha512", "ssdeep", "imphash", "tlsh"}
    if name.lower() in hash_types:
        return name.lower()

    # Network types
    if name in {"ip-src", "ip-dst", "ip"}:
        return "ip-dst" if name == "ip" else name
    if name in {"domain", "hostname"}:
        return name
    if name == "url":
        return "url"
    if name == "port":
        return "port"

    # Other known types
    type_map = {
        "filename": "filename",
        "mimetype": "mime-type",
        "size-in-bytes": "size-in-bytes",
        "link": "link",
        "comment": "comment",
        "text": "text",
    }
    return type_map.get(name)


def _infer_category_from_type(misp_type: str) -> str:
    """Infer MISP category from attribute type.

    Args:
        misp_type: MISP attribute type

    Returns:
        MISP category string
    """
    categories = {
        # Payload delivery
        "md5": "Payload delivery",
        "sha1": "Payload delivery",
        "sha256": "Payload delivery",
        "sha512": "Payload delivery",
        "filename": "Payload delivery",
        "ssdeep": "Payload delivery",
        "imphash": "Payload delivery",
        "tlsh": "Payload delivery",
        # Network activity
        "ip-src": "Network activity",
        "ip-dst": "Network activity",
        "domain": "Network activity",
        "hostname": "Network activity",
        "url": "Network activity",
        "port": "Network activity",
        # External analysis
        "link": "External analysis",
        "comment": "External analysis",
    }
    return categories.get(misp_type, "Other")


def _should_be_ids(misp_type: str) -> bool:
    """Determine if attribute type should have to_ids=True.

    Args:
        misp_type: MISP attribute type

    Returns:
        True if the attribute should be used for IDS
    """
    ids_types = {
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "ssdeep",
        "imphash",
        "tlsh",
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "url",
        "filename",
    }
    return misp_type in ids_types


def _parse_dsl(field_def: str) -> Dict:
    """Parse compact DSL string into a field definition dict.

    DSL syntax:
        path                           - simple path
        path1 | path2                  - fallback paths
        path (type)                    - path with explicit MISP type hint
        path1 | path2 (type)           - fallback paths with type hint
        (int) path                     - type coercion (prefix)
        literal text (no path chars)   - static value
        {{#ref path}}                  - path reference (for tags)
        {{#ref path (type)}}           - path reference with type hint
        {{#handler path}}              - handler invocation
        ^ path                         - parent context reference
        {{#Comment ...}}               - inline comment (added to MISP attribute)

    Returns:
        Dict with keys: paths, coerce, value, handler, parent_ref, comment, type_hint
    """
    result = {}
    text = field_def.strip()

    # Extract inline comments: {{#Comment ...}} - save the text for MISP attribute comment
    comment_match = re.search(r"\{\{#[Cc]omment\s+([^}]*)\}\}", text)
    if comment_match:
        result["comment"] = comment_match.group(1).strip()
        text = re.sub(r"\s*\{\{#[Cc]omment\s+[^}]*\}\}\s*", "", text).strip()

    # Check for block-style if: {{#if cond}}true_block{{#else}}false_block{{/if}}
    block_if_re = re.match(
        r"^\{\{#if\s+(.+?)\}\}(.*?)(?:\{\{#else\}\}(.*?))?\{\{/if\}\}\s*$", text, flags=re.DOTALL
    )
    if block_if_re:
        result["handler"] = "if"
        result["handler_path"] = block_if_re.group(1).strip()
        result["true_block"] = (block_if_re.group(2) or "").strip()
        result["false_block"] = (
            (block_if_re.group(3) or "").strip() if block_if_re.group(3) is not None else None
        )
        return result

    # Check for block-style foreach: {{#foreach path [limit]}}template{{/foreach}}
    # Supports optional filter syntax: {{#foreach path[field=val1,val2] [limit]}}template{{/foreach}}
    # Optional limit parameter controls max iterations (default 1000)
    block_foreach_re = re.match(
        r"^\{\{#foreach\s+(.+?)\}\}(.*?)\{\{/foreach\}\}\s*$", text, flags=re.DOTALL
    )
    if block_foreach_re:
        result["handler"] = "foreach"
        path_and_limit = block_foreach_re.group(1).strip()
        # Check for optional limit at end: "path 10" or "path[filter] 10"
        limit_match = re.match(r"^(.+?)\s+(\d+)$", path_and_limit)
        if limit_match:
            result["handler_path"] = limit_match.group(1).strip()
            result["limit"] = int(limit_match.group(2))
        else:
            result["handler_path"] = path_and_limit
            result["limit"] = MAX_FOREACH_ITERATIONS  # Default limit
        result["template"] = block_foreach_re.group(2) or ""
        return result

    # Check for handler syntax: {{#handler}} or {{#handler path}} or {{#handler path (type)}}
    handler_match = re.match(r"\{\{#(\w+)(?:\s+(.+?))?\}\}", text.strip())
    if handler_match:
        result["handler"] = handler_match.group(1)
        handler_path = (handler_match.group(2) or "").strip()
        # Check for type hint suffix: (type) at the end - e.g., "path | path2 (ip-dst)"
        type_hint_match = re.search(r"\s*\(([a-z][a-z0-9-]*)\)\s*$", handler_path, re.IGNORECASE)
        if type_hint_match:
            result["type_hint"] = type_hint_match.group(1).lower()
            # Normalize 'ip' to 'ip-dst' for consistency
            if result["type_hint"] == "ip":
                result["type_hint"] = "ip-dst"
            handler_path = handler_path[: type_hint_match.start()].strip()
        result["handler_path"] = handler_path
        return result

    # Check for type coercion prefix: (int) path
    coerce_match = re.match(r"\((\w+)\)\s*(.+)", text)
    if coerce_match:
        result["coerce"] = coerce_match.group(1)
        text = coerce_match.group(2).strip()

    # Check for parent reference: ^
    if text.startswith("^"):
        result["parent_ref"] = True
        text = text[1:].strip()

    # Check for type hint suffix: (type) at the end - e.g., "path | path2 (ip-dst)"
    type_hint_match = re.search(r"\s*\(([a-z][a-z0-9-]*)\)\s*$", text, re.IGNORECASE)
    if type_hint_match:
        result["type_hint"] = type_hint_match.group(1).lower()
        # Normalize 'ip' to 'ip-dst' for consistency
        if result["type_hint"] == "ip":
            result["type_hint"] = "ip-dst"
        text = text[: type_hint_match.start()].strip()

    # Check for fallback paths: path1 | path2
    if "|" in text:
        result["paths"] = [p.strip() for p in text.split("|")]
    elif "." in text or "_" in text or text.isidentifier():
        # Looks like a path
        result["paths"] = [text]
    else:
        # Static literal value
        result["value"] = text

    return result


def _resolve_dsl_in_comment(comment: str, data: Dict, api_context: Optional[Dict] = None) -> str:
    """Resolve DSL templates in comment strings.

    Args:
        comment: Comment string that may contain DSL templates like {{#ref path}}
        data: API response data for resolving references
        api_context: Optional API context

    Returns:
        Comment string with DSL templates resolved to actual values
    """
    if not comment or not isinstance(comment, str):
        return comment or ""

    # Pattern to match DSL templates: {{#handler args}}
    pattern = r"\{\{#(\w+)(?:\s+([^}]+))?\}\}"

    def replace_template(match):
        handler_name = match.group(1)
        handler_path = (match.group(2) or "").strip()

        if handler_name == "ref":
            # {{#ref path}} - resolve reference
            if handler_path:
                if "|" in handler_path:
                    tokens = [p.strip() for p in handler_path.split("|")]
                else:
                    tokens = [handler_path]
                value = _resolve_ref_with_literals(data, tokens)
                return str(value) if value is not None else ""
        elif handler_name == "build_link":
            # {{#build_link ioc_type}} - build link
            ioc_type = handler_path.strip() if handler_path else ""
            type_config = IOC_TYPE_CONFIG.get(ioc_type or "", {})
            value_fields = type_config.get("value_fields", [])

            ioc_value = get_first(data, value_fields) if value_fields else None
            if ioc_value:
                link_template = type_config.get("link_template")
                if link_template:
                    fmt_kwargs = {"value": ioc_value}
                    base = None
                    if api_context and isinstance(api_context.get("api_url"), str):
                        base = api_context.get("api_url")
                    else:
                        base = os.getenv("RL_API_URL")
                    if not base:
                        base = "https://a1000.reversinglabs.com"
                    fmt_kwargs["api_url"] = base.rstrip("/")
                    return link_template.format(**fmt_kwargs)

        # If we can't resolve, return the original template
        return match.group(0)

    return re.sub(pattern, replace_template, comment)


def _resolve_ref_with_literals(data: Dict, tokens: List[str]) -> Any:
    """Resolve ref tokens where quoted tokens are literal fallbacks.

    Rules:
    - Tokens is an ordered list of fallbacks (already split on '|').
    - If a token is a paired single-quote or double-quote string, return the unquoted literal.
    - Otherwise treat the token as a JSON path and resolve via get_first.
    - Only ``None`` (missing/null) triggers the next fallback; empty string "", 0, False are valid values.
    """
    if not tokens:
        return None

    for t in tokens:
        if not isinstance(t, str):
            continue
        tok = t.strip()
        # literal token if properly paired quotes
        if len(tok) >= 2 and (
            (tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'")
        ):
            return tok[1:-1]

        # otherwise treat as path
        val = get_first(data, [tok])
        # Treat None or empty/whitespace-only strings as missing so fallbacks apply
        if val is None:
            continue
        if isinstance(val, str) and val.strip() == "":
            continue
        return val

    return None


def _resolve_foreach_template(template: str, item_data: Dict) -> Any:
    """Resolve a foreach template with item data context.

    Processes {{#ref ...}} expressions within the template, resolving paths
    relative to the current item in the foreach iteration.

    Args:
        template: Template string with {{#ref ...}} expressions
        item_data: Current item data (dict context for resolution)

    Returns:
        Resolved value (string or original type if single ref)
    """
    if not template:
        return None

    # Check if template is a single {{#ref path}} - return value directly (preserve type)
    single_ref = re.match(r"^{{\s*#ref\s+(.+?)\s*}}$", template.strip())
    if single_ref:
        path = single_ref.group(1).strip()
        # Handle fallback paths: path1 | path2 | "LITERAL"
        tokens = [t.strip() for t in path.split("|")]
        return _resolve_ref_with_literals(item_data, tokens)

    # Template has multiple refs or mixed content - resolve and concatenate as string
    result = template

    # Find all {{#ref ...}} patterns and resolve them
    def replace_ref(match):
        path = match.group(1).strip()
        tokens = [t.strip() for t in path.split("|")]
        val = _resolve_ref_with_literals(item_data, tokens)
        return str(val) if val is not None else ""

    result = re.sub(r"{{\s*#ref\s+(.+?)\s*}}", replace_ref, result)

    return result if result else None


def _determine_misp_type(value: Any) -> str:
    """Determine the appropriate MISP attribute type based on the value.

    Args:
        value: The attribute value

    Returns:
        MISP type string ('text', 'float', 'boolean', 'datetime', etc.)
    """
    if isinstance(value, bool):
        return "boolean"
    elif isinstance(value, (int, float)):
        return "float"
    elif isinstance(value, str):
        # Check if it looks like a datetime
        if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
            return "datetime"
        elif re.match(r"^\d{4}-\d{2}-\d{2}", value):
            return "datetime"
        else:
            return "text"
    else:
        # Default to text for unknown types
        return "text"


def _build_attributes_from_def(
    data: Dict,
    obj_def: Dict,
    original_value: str,
    results: Dict,
    api_context: Optional[Dict] = None,
) -> List[Dict]:
    """Build attributes from an object definition.

    Args:
        data: API response data
        obj_def: Object definition from mappings
        original_value: Original IOC value
        results: Results container (for adding tags)

    Returns:
        List of MISP attributes
    """
    attributes = []

    for field_name, field_def in obj_def.items():
        actual_field_name = field_name  # May be modified by handlers
        # Check for ! prefix - promotes attribute to event-level
        promote_to_event = field_name.startswith("!")
        if promote_to_event:
            field_name = field_name[1:]  # Strip the ! prefix
            actual_field_name = field_name

        # Strip numeric index suffix (e.g., text#0 -> text, text#1 -> text)
        # Also supports legacy text[0] syntax
        # This allows multiple attributes of the same type in JSON mappings
        index_match = re.match(r"^(.+?)(?:#\d+|\[\d+\])$", field_name)
        if index_match:
            field_name = index_match.group(1)
            actual_field_name = field_name

        # Skip directives (obj:type, obj:parent, etc.)
        if field_name.startswith("obj:"):
            continue
        if field_name.startswith("_") or field_name.startswith("#"):
            continue

        # Skip array iteration keys that are object definitions (handled separately)
        # BUT allow string definitions with [] suffix (these are foreach tag/attribute definitions)
        if field_name.endswith("[]") and isinstance(field_def, dict):
            # Raw dict with obj:type or obj:path is an object iteration - skip here
            if "obj:type" in field_def or "obj:path" in field_def:
                continue

        # Parse string DSL into dict
        if isinstance(field_def, str):
            field_def = _parse_dsl(field_def)
        elif not isinstance(field_def, dict):
            continue

        # After parsing, skip object iteration keys that don't have foreach handler
        if field_name.endswith("[]") and field_def.get("handler") != "foreach":
            continue

        # Check if this is a tag definition (starts with : or contains : but not obj:)
        is_tag = field_name.startswith(":") or (
            ":" in field_name and not field_name.startswith("obj:")
        )

        # Handle handlers that set the value
        value = None
        handler_name = field_def.get("handler")
        handler_path = field_def.get("handler_path", "")
        dynamic_field_name = None

        if handler_name == "ref":
            # {{#ref path}} - extracts value from API response
            paths = [handler_path] if handler_path else []
            # Parse fallback tokens from handler_path (path1 | path2 | "LITERAL")
            if paths and "|" in paths[0]:
                tokens = [p.strip() for p in paths[0].split("|")]
            else:
                tokens = paths
            value = _resolve_ref_with_literals(data, tokens) if tokens else None

            # If value is an empty string after trimming, treat as None for attribute creation
            if isinstance(value, str):
                value = value.strip()
                if value == "":
                    value = None
            # If this field is a tag-style field (contains ':'), create a tag
            if value is not None and is_tag:
                tag_name = field_name.lstrip(":")
                if ":" in tag_name:
                    parts = tag_name.split(":", 1)
                    namespace = parts[0]
                    key = parts[1]
                else:
                    namespace = "rl"
                    key = tag_name
                tag = create_tag(namespace, key, str(value))
                results["Tag"].append(tag)
                continue

        elif handler_name == "if":
            # Block conditional: evaluate condition then render selected block
            cond_raw = handler_path or ""
            cond_tokens = [p.strip() for p in cond_raw.split("|")] if cond_raw else []
            cond_val = _resolve_ref_with_literals(data, cond_tokens) if cond_tokens else None
            cond_truth = bool(cond_val)

            true_block = field_def.get("true_block", "")
            false_block = field_def.get("false_block")
            selected = true_block if cond_truth else false_block

            if selected is None:
                value = None
            else:
                sel_def = _parse_dsl(selected)
                if sel_def.get("handler") == "ref":
                    p = sel_def.get("handler_path", "")
                    tokens = [t.strip() for t in p.split("|")] if "|" in p else ([p] if p else [])
                    value = _resolve_ref_with_literals(data, tokens) if tokens else None
                elif "value" in sel_def:
                    value = sel_def["value"]
                elif "paths" in sel_def:
                    value = get_first(data, sel_def["paths"])
                else:
                    value = None
        elif handler_name == "format_stats":
            # Format statistics object into readable summary
            stats_data = get_first(data, [handler_path])
            if stats_data and isinstance(stats_data, dict):
                value = _format_statistics(stats_data)
            else:
                continue
        elif handler_name == "json_dump":
            # Dump entire API response as JSON
            value = json.dumps(data, indent=2, default=str)
        elif handler_name == "av_details":
            # Format AV scanner details as list of detections
            av_data = get_first(data, [handler_path]) if handler_path else data.get("av_scanners")
            value = _format_av_details(av_data)
        elif handler_name == "build_summary":
            # Build aggregated summary from multiple data sources (file)
            value = _build_summary(data)
        elif handler_name == "summary":
            # Unified summary handler for all IOC types
            value = _build_unified_summary(data, api_context)
        elif handler_name == "list_items":
            # {{#list_items path field}} - extract field from list items, join with comma
            # e.g. {{#list_items top_threats threat_name}} -> "Trojan.X, Malware.Y"
            parts = handler_path.split(None, 1) if handler_path else []
            if len(parts) >= 1:
                list_path = parts[0]
                field_key = parts[1] if len(parts) > 1 else "value"
                items = get_first(data, [list_path])
                if items and isinstance(items, list):
                    values = []
                    for item in items[:10]:  # Limit to 10 items
                        if isinstance(item, dict):
                            v = item.get(field_key)
                            if v:
                                values.append(str(v))
                        elif item:
                            values.append(str(item))
                    if values:
                        value = ", ".join(values)
                    else:
                        continue
                else:
                    continue
            else:
                continue
        elif handler_name == "build_link":
            # {{#build_link ioc_type}} - construct Spectra Analyze link using configuration
            ioc_type = handler_path.strip() if handler_path else ""
            type_config = IOC_TYPE_CONFIG.get(ioc_type, {})
            value_fields = type_config.get("value_fields", [])

            ioc_value = get_first(data, value_fields) if value_fields else None
            if ioc_value:
                link_template = type_config.get("link_template")
                if link_template:
                    fmt_kwargs = {"value": ioc_value}
                    base = None
                    if api_context and isinstance(api_context.get("api_url"), str):
                        base = api_context.get("api_url")
                    else:
                        base = os.getenv("RL_API_URL")
                    if not base:
                        base = "https://a1000.reversinglabs.com"
                    fmt_kwargs["api_url"] = (base).rstrip("/")
                    value = link_template.format(**fmt_kwargs)
                elif ioc_type == "url":
                    # URL needs special encoding
                    base = None
                    if api_context and isinstance(api_context.get("api_url"), str):
                        base = api_context.get("api_url")
                    else:
                        base = os.getenv("RL_API_URL")
                    if not base:
                        base = "https://a1000.reversinglabs.com"
                    base = (base).rstrip("/")
                    value = f"{base}/url/{quote(ioc_value, safe='')}/analysis/url/"
                else:
                    # Fallback for unknown types
                    base = None
                    if api_context and isinstance(api_context.get("api_url"), str):
                        base = api_context.get("api_url")
                    else:
                        base = os.getenv("RL_API_URL")
                    base = (base).rstrip("/")
                    value = f"{base}/{ioc_type}/{ioc_value}/"
        elif handler_name == "tags_from":
            # {{#tags_from path field [tagkey]}} - create tags from list items
            # Tag key is derived from mapping key (e.g., "rl:riskscore" -> namespace="rl", key="riskscore")
            # Optional 3rd arg overrides the key portion
            parts = handler_path.split() if handler_path else []
            if len(parts) >= 1:
                list_path = parts[0]
                field_key = parts[1] if len(parts) > 1 else ""
                # Use mapping key for tag name (e.g., "rl:riskscore" -> "riskscore")
                # Fall back to explicit 3rd arg, then field_key
                if ":" in field_name:
                    tag_namespace, tag_key = field_name.split(":", 1)
                else:
                    tag_namespace = "rl"
                    tag_key = field_name
                # Allow explicit override via 3rd argument
                if len(parts) > 2:
                    tag_key = parts[2]
                items = get_first(data, [list_path])
                if items and isinstance(items, list):
                    for item in items[:10]:
                        if isinstance(item, dict):
                            v = item.get(field_key)
                            if v:
                                tag = create_tag(tag_namespace, tag_key, str(v))
                                results["Tag"].append(tag)
                        elif item:
                            tag = create_tag(tag_namespace, tag_key, str(item))
                            results["Tag"].append(tag)
            continue  # Don't create attribute, only tags
        elif handler_name == "foreach":
            # {{#foreach path}}template{{/foreach}} - iterate over array, resolve template per item
            # Two modes based on key format:
            #   - key[] or key:[] → creates MULTIPLE tags/attributes (one per item)
            #   - key (no []) → AGGREGATES into single value (comma-joined)
            array_path = handler_path.strip() if handler_path else ""
            template = field_def.get("template", "")

            # Parse optional filter from path: path[field=val1,val2]
            foreach_filter = None
            filter_match = re.match(r"^(.+?)\[([^\]]+)\]$", array_path)
            if filter_match:
                array_path = filter_match.group(1)
                filter_expr = filter_match.group(2)
                # Parse filter: field=val1,val2
                if "=" in filter_expr:
                    filter_field, filter_vals = filter_expr.split("=", 1)
                    foreach_filter = (
                        filter_field.strip(),
                        [v.strip() for v in filter_vals.split(",")],
                    )

            # Get the array data
            items = get_first(data, [array_path])
            if not items or not isinstance(items, list):
                continue

            # Check if this is multiple mode (key ends with [])
            is_multiple_mode = field_name.endswith("[]")

            # Strip [] suffix from field_name if present (array indicator)
            clean_field_name = re.sub(r"\[\]$", "", field_name)

            # Check if this is a tag (namespace:key: or namespace:key:[])
            # Tags end with : before optional []
            is_foreach_tag = clean_field_name.endswith(":")
            if is_foreach_tag:
                clean_field_name = clean_field_name.rstrip(":")

            # Parse tag namespace and key
            if ":" in clean_field_name:
                tag_namespace, tag_key = clean_field_name.split(":", 1)
                tag_key = tag_key.rstrip(":")  # Remove trailing colons
            else:
                tag_namespace = "rl"
                tag_key = clean_field_name

            # Collect resolved values
            resolved_values = []

            # Get limit from parsed field_def (default MAX_FOREACH_ITERATIONS)
            max_limit = field_def.get("limit", MAX_FOREACH_ITERATIONS)

            # Iterate over items up to the limit
            for item in items[:max_limit]:
                # Apply filter if specified
                if foreach_filter:
                    filter_field, filter_vals = foreach_filter
                    if isinstance(item, dict):
                        item_val = str(item.get(filter_field, ""))
                        if item_val not in filter_vals:
                            continue
                    else:
                        continue

                # Resolve the template with item as data context
                item_data = item if isinstance(item, dict) else {"value": item}
                resolved = _resolve_foreach_template(template, item_data)

                if resolved is None or (isinstance(resolved, str) and not resolved.strip()):
                    continue

                # In multiple mode, strip each value; in aggregate mode, preserve template formatting
                resolved_str = str(resolved).strip() if is_multiple_mode else str(resolved)
                resolved_values.append(resolved_str)

            # Handle output based on mode
            if is_multiple_mode:
                # Multiple mode: create separate tag/attribute for each value
                for resolved_str in resolved_values:
                    if is_foreach_tag or is_tag:
                        # Create tag
                        tag = create_tag(tag_namespace, tag_key, resolved_str)
                        results["Tag"].append(tag)
                    else:
                        # Create attribute
                        attr = MISPAttribute()
                        attr.type = field_def.get("type_hint") or clean_field_name
                        attr.value = resolved_str
                        if field_def.get("comment"):
                            attr.comment = field_def["comment"]
                        attributes.append(attr)
            else:
                # Aggregate mode: concatenate values (separator controlled in template)
                if resolved_values:
                    joined_value = "".join(resolved_values)
                    if is_foreach_tag or is_tag:
                        # Create single tag with joined value
                        tag = create_tag(tag_namespace, tag_key, joined_value)
                        results["Tag"].append(tag)
                    else:
                        # Create single attribute with joined value
                        value = joined_value
                        # Fall through to normal attribute creation below

            # If multiple mode or aggregate mode with tags, we're done
            if is_multiple_mode or (is_foreach_tag or is_tag):
                continue
            # For aggregate mode with attributes, fall through if we have a value
            if not resolved_values:
                continue
        elif handler_name == "dns_value":
            # Format DNS record type/value into MISP attribute
            type_val = get_first(data, ["type"])
            value_val = get_first(data, ["value"])
            if type_val and value_val:
                # The handler returns the attribute type, and we use value_val as the value
                dynamic_field_name = _format_dns_value(type_val, value_val)
                value = value_val
            else:
                continue
        elif handler_name == "dns_records":
            # {{#dns_records TYPE path}} - filter DNS records by type, return values
            # handler_path format: "TYPE path" e.g. "A last_dns_records"
            parts = handler_path.split(None, 1) if handler_path else []
            if len(parts) == 2:
                record_type = parts[0].upper()
                records_path = parts[1]
                records = get_first(data, [records_path])
                if records and isinstance(records, list):
                    values: list[str] = []
                    for r in records:
                        if isinstance(r, dict) and str(r.get("type", "")).upper() == record_type:
                            v = r.get("value")
                            if v:
                                values.append(str(v))
                    if values:
                        # Return first value for now (MISP attributes are single-valued)
                        # For multi-value, we'd need to create multiple attributes
                        value = values[0] if len(values) == 1 else ", ".join(values)
                    else:
                        continue
                else:
                    continue
            else:
                continue
        elif handler_name is not None:
            # Unknown handler, skip
            continue
        else:
            # No handler - get value from data using paths
            paths = field_def.get("paths", [field_name])
            if isinstance(paths, str):
                paths = [paths]

            # Check for static value
            if "value" in field_def:
                value = field_def["value"]
            else:
                value = get_first(data, paths)

        # Use dynamic field name if set by handler
        actual_field_name = dynamic_field_name or field_name

        # Normalize trimmed-empty strings to None (suppresses attribute/tag creation)
        # Skip stripping for foreach aggregate mode (user controls separator/formatting)
        is_foreach_aggregate = (
            handler_name == "foreach" and not is_multiple_mode and resolved_values
        )
        if isinstance(value, str) and not is_foreach_aggregate:
            value = value.strip()
            if value == "":
                continue

        if value is None:
            continue

        # Apply type coercion
        if "coerce" in field_def:
            value = coerce(value, field_def["coerce"])
            if value is None:
                continue

        # Skip tag entries for attribute creation (already handled above or is a tag-only field)
        if is_tag:
            continue

        # Create attribute with optional comment
        attr_comment = field_def.get("comment", "")
        if attr_comment:
            attr_comment = _resolve_dsl_in_comment(attr_comment, data, api_context)
        # Priority: type_hint from DSL > inferred from field name > determined from value
        misp_type = (
            field_def.get("type_hint")
            or _infer_misp_type_from_name(actual_field_name)
            or _determine_misp_type(value)
        )
        attr = create_misp_attribute(
            misp_type=misp_type,
            value=value,
            object_relation=actual_field_name,
            comment=attr_comment,
        )
        attributes.append(attr)

        # If !prefix was used, also create an event-level attribute for correlation
        # Treat empty string/False/0 as valid values; only None should suppress creation
        if promote_to_event and value is not None:
            # Priority: type_hint from DSL > inferred from field name > determined from value
            event_misp_type = (
                field_def.get("type_hint")
                or _infer_misp_type_from_name(actual_field_name)
                or misp_type
            )
            event_attr = {
                "uuid": str(uuid.uuid4()),
                "type": event_misp_type,
                "value": value,
                "category": _infer_category_from_type(event_misp_type),
                "to_ids": _should_be_ids(event_misp_type),
                "disable_correlation": False,
            }
            if attr_comment:
                event_attr["comment"] = attr_comment
            results["Attribute"].append(event_attr)

        # Create tag if specified
        if field_def.get("as_tag") and value:
            tag = create_tag("rl", field_name, str(value))
            results["Tag"].append(tag)

    return attributes


def _process_array_objects(
    data: Dict,
    ioc_mappings: Dict,
    results: Dict,
    original_value: str,
    created_objects: Dict[str, Dict],
) -> None:
    """Process object definitions with array notation (obj_name[]).

    Creates one object per array item. Uses DSL format:
        "dns-record[]": {
            "obj:type": "dns-record",
            "obj:path": "last_dns_records[]",
            "obj:parent": "report",
            "text": "type",
            "queried-domain": "^ requested_domain"
        }

    Directives:
        obj:type   - MISP object type to create
        obj:path   - JSON path to array (with [] suffix)
        obj:parent - Parent object name for linking
        ^ path     - Reference parent context (not array item)
    """

    for obj_name, obj_def in ioc_mappings.items():
        # Only process array object definitions (name ends with [])
        if not obj_name.endswith("[]"):
            continue

        if not isinstance(obj_def, dict):
            continue

        # Get object type (strip [] from obj_name as fallback)
        obj_type = obj_def.get("obj:type", obj_name[:-2])

        # Get array path from obj:path directive
        array_path_directive = obj_def.get("obj:path", "")
        if not array_path_directive:
            continue

        # Remove [] suffix from path
        array_path = array_path_directive.rstrip("[]")

        # Get parent for relationship linking
        parent_name = obj_def.get("obj:parent") or obj_def.get("_parent")
        parent_obj = created_objects.get(parent_name) if parent_name else None

        # Get the array to iterate
        items = iterate_array(data, array_path)
        if not items:
            continue

        for item in items:
            if not isinstance(item, dict):
                # Handle simple values (e.g., array of strings)
                item = {"_value": item}

            attributes = []

            # Process each field in the object definition
            for field_name, field_def in obj_def.items():
                # Skip directives
                if (
                    field_name.startswith("obj:")
                    or field_name.startswith("_")
                    or field_name.startswith("#")
                ):
                    continue

                # Check if this is a tag definition
                is_tag = ":" in field_name and not field_name.startswith("obj:")

                # Parse DSL string
                if isinstance(field_def, str):
                    parsed = _parse_dsl(field_def)
                else:
                    parsed = field_def if isinstance(field_def, dict) else {}

                # Handle parent reference (^ path)
                if parsed.get("parent_ref"):
                    paths = parsed.get("paths", [])
                    value = get_first(data, paths)  # Use parent data, not item
                # Handle handlers
                elif parsed.get("handler"):
                    # Skip unimplemented handlers for now
                    continue
                # Handle static value
                elif "value" in parsed:
                    value = parsed["value"]
                # Normal path lookup in item
                else:
                    paths = parsed.get("paths", [field_name])
                    value = get_first(item, paths)

                if value is None:
                    continue

                # Apply coercion
                if parsed.get("coerce"):
                    value = coerce(value, parsed["coerce"])
                    if value is None:
                        continue

                # Handle tags
                if is_tag:
                    tag_name = field_name
                    if ":" in tag_name:
                        parts = tag_name.split(":", 1)
                        tag = create_tag(parts[0], parts[1], str(value))
                    else:
                        tag = create_tag("rl", tag_name, str(value))
                    if tag not in results["Tag"]:
                        results["Tag"].append(tag)
                    continue

                # Create attribute
                misp_type = _determine_misp_type(value)
                attr = create_misp_attribute(
                    misp_type=misp_type,
                    value=value,
                    object_relation=field_name,
                )
                attributes.append(attr)

            # Create object if we have attributes
            if attributes:
                obj = create_misp_object(obj_type, attributes)
                results["Object"].append(obj)

                # Link to parent
                if parent_obj:
                    ref = create_object_reference(
                        parent_obj["uuid"], obj["uuid"], RELATIONSHIP_TYPES["CONTAINS"]
                    )
                    results["ObjectReference"].append(ref)


def _format_statistics(stats: Any) -> str:
    """Format statistics data into readable summary text.

    Handles dict, list, and string data types.
    """
    if isinstance(stats, dict):
        parts = []

        # Handle AV scanner summary format
        scanner_count = stats.get("scanner_count", 0)
        scanner_match = stats.get("scanner_match", 0)
        scanner_percent = stats.get("scanner_percent", 0)
        if scanner_count:
            parts.append(f"AV detections: {scanner_match}/{scanner_count} ({scanner_percent:.1f}%)")

        vendor_count = stats.get("vendor_count", 0)
        vendor_match = stats.get("vendor_match", 0)
        if vendor_count:
            parts.append(f"Vendors: {vendor_match}/{vendor_count}")

        # Handle downloaded files statistics format
        total = stats.get("total", 0)
        if total:
            parts.append(f"Total downloads: {total}")

        malicious = stats.get("malicious", 0)
        if malicious:
            parts.append(f"Malicious: {malicious}")

        suspicious = stats.get("suspicious", 0)
        if suspicious:
            parts.append(f"Suspicious: {suspicious}")

        unknown = stats.get("unknown", 0)
        if unknown:
            parts.append(f"Unknown: {unknown}")

        # Add date ranges if available
        first_seen = stats.get("first_download")
        last_seen = stats.get("last_download")
        if first_seen:
            parts.append(f"First seen: {first_seen}")
        if last_seen:
            parts.append(f"Last seen: {last_seen}")

        return " | ".join(parts) if parts else ""

    elif isinstance(stats, list):
        # If it's a list, format as comma-separated values
        if stats:
            return f"AV results: {', '.join(str(item) for item in stats[:10])}" + (
                "..." if len(stats) > 10 else ""
            )
        return ""

    elif isinstance(stats, str):
        # If it's a string, return it as-is (truncated if too long)
        return stats[:200] + ("..." if len(stats) > 200 else "")

    else:
        # For other types, convert to string
        return str(stats)[:200]


def _format_av_details(av_scanners: Any) -> str:
    """Format AV scanner results as a detailed list.

    Returns only scanners with detections (non-empty results).
    Format: "scanner_name: result" per line
    """
    if not isinstance(av_scanners, list):
        return ""

    lines = []
    for scanner in av_scanners:
        if not isinstance(scanner, dict):
            continue
        name = scanner.get("name", "Unknown")
        result = scanner.get("result")
        # Only include scanners with actual detections
        if result and result not in ("", "clean", "Clean", None):
            lines.append(f"{name}: {result}")

    if not lines:
        return "No detections from any scanner"

    return "\n".join(sorted(lines))


def _build_summary(data: Dict) -> str:
    """Build aggregated summary from multiple data sources.

    Combines: classification, risk score, AV stats, file info into one summary.
    """
    parts = []

    # Classification and risk
    sample = data.get("sample_summary", {})
    classification = sample.get("classification")
    if classification:
        parts.append(f"Classification: {classification}")

    riskscore = sample.get("riskscore")
    if riskscore is not None:
        parts.append(f"Risk: {riskscore}/10")

    threat_level = sample.get("threat_level")
    if threat_level:
        parts.append(f"Threat: {threat_level}")

    # AV summary
    av_summary = data.get("av_scanners_summary", {})
    scanner_match = av_summary.get("scanner_match", 0)
    scanner_count = av_summary.get("scanner_count", 0)
    if scanner_count:
        parts.append(f"AV: {scanner_match}/{scanner_count}")

    # File info
    file_type = sample.get("file_type")
    if file_type:
        parts.append(f"Type: {file_type}")

    file_size = sample.get("file_size")
    if file_size:
        if file_size >= 1024 * 1024:
            size_str = f"{file_size / (1024 * 1024):.1f}MB"
        elif file_size >= 1024:
            size_str = f"{file_size / 1024:.1f}KB"
        else:
            size_str = f"{file_size}B"
        parts.append(f"Size: {size_str}")

    # Classification source
    source = sample.get("classification_source")
    if source:
        parts.append(f"Source: {source}")

    return "\n".join(parts) if parts else "No summary data available"


def _build_domain_summary(data: Dict) -> str:
    """Build summary for domain enrichment.

    Combines: download stats, top threats, third party reputation.
    """
    parts = []

    # Download statistics
    stats = data.get("downloaded_files_statistics", {})
    if stats:
        total = stats.get("total", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        parts.append(f"Downloads: {total} total, {malicious} malicious, {suspicious} suspicious")

    # Third party reputation summary
    tpr = data.get("third_party_reputations", {})
    tpr_stats = tpr.get("statistics", {})
    if tpr_stats:
        mal = tpr_stats.get("malicious", 0)
        total = tpr_stats.get("total", 0)
        if mal > 0:
            parts.append(f"Reputation: {mal}/{total} vendors flagged malicious")
        else:
            parts.append(f"Reputation: Clean ({total} vendors)")

    # Top threats summary
    top_threats = data.get("top_threats", [])
    if top_threats:
        threat_names = [t.get("threat_name", "") for t in top_threats[:3] if t.get("threat_name")]
        if threat_names:
            parts.append(f"Top threats: {', '.join(threat_names)}")

    # Timestamps
    last_seen = data.get("last_seen")
    if last_seen:
        parts.append(f"Last seen: {last_seen[:10]}")

    return " | ".join(parts) if parts else "No summary data available"


def _build_unified_summary(data: Dict, api_context: Optional[Dict[str, Any]] = None) -> str:
    """Unified summary builder for all IOC types.

    Aggregates information from ALL available data sources to provide
    comprehensive summary including:
    - File analysis (classification, risk, AV stats, file info)
    - Download statistics (domain, IP, URL activity)
    - Third-party reputation data
    - Threat intelligence
    - Timestamps and metadata
    """

    def add_unique(label: str, value, condition: Union[bool, Callable] = True, formatter=None):
        """Add item to parts if condition met and not already present."""
        # Evaluate condition - if it's callable, call it with value, otherwise use as boolean
        cond_result = condition(value) if callable(condition) else condition
        if cond_result and value is not None and value != "" and not any(label in p for p in parts):
            formatted = formatter(value) if formatter else str(value)
            parts.append(f"{label}: {formatted}")

    def format_size(bytes_val):
        """Format file size in human readable format."""
        if bytes_val >= 1024 * 1024:
            return f"{bytes_val / (1024 * 1024):.1f}MB"
        elif bytes_val >= 1024:
            return f"{bytes_val / 1024:.1f}KB"
        return f"{bytes_val}B"

    parts = []

    # IOC value first
    ioc_value = None
    ioc_label = "IOC"
    if api_context:
        ioc_value = api_context.get("original_value")
        ioc_type = api_context.get("ioc_type")
        if ioc_type:
            ioc_label = str(ioc_type).upper()
        if not ioc_value and ioc_type:
            type_cfg = IOC_TYPE_CONFIG.get(str(ioc_type)) or {}
            ioc_value = get_first(data, type_cfg.get("value_fields", []))
    if ioc_value:
        parts.append(f"{ioc_label}: {ioc_value}")

    # File/Sample Analysis Data
    sample = data.get("sample_summary", {})
    if sample:
        add_unique("Classification", sample.get("classification"))
        add_unique(
            "Risk Score", sample.get("riskscore"), lambda x: x is not None, lambda x: f"{x}/10"
        )
        add_unique("Threat Level", sample.get("threat_level"))
        add_unique("Trust Factor", sample.get("trust_factor"))
        add_unique("File Type", sample.get("file_type"))
        add_unique("File Size", sample.get("file_size"), formatter=format_size)
        add_unique(
            "Extracted Files", sample.get("extracted_file_count"), lambda x: x is not None and x > 0
        )
        add_unique("Source", sample.get("classification_source"))
        add_unique("Reason", sample.get("classification_reason"))

    # AV Scanner Summary
    av = data.get("av_scanners_summary", {})
    if av.get("scanner_count"):
        match, count, pct = (
            av.get("scanner_match", 0),
            av["scanner_count"],
            av.get("scanner_percent", 0),
        )
        add_unique("AV Detections", f"{match}/{count} ({pct:.1f}%)")

    # Download Statistics
    stats = data.get("downloaded_files_statistics", {})
    if stats:
        add_unique("Total Downloads", stats.get("total"))
        add_unique("Malicious Downloads", stats.get("malicious"))
        add_unique("Suspicious Downloads", stats.get("suspicious"))
        add_unique("Unknown Downloads", stats.get("unknown"))
        add_unique("First Download", stats.get("first_download"))
        add_unique("Last Download", stats.get("last_download"))

    # Third Party Reputation
    tpr = data.get("third_party_reputations", {}).get("statistics", {})
    if tpr:
        mal, total = tpr.get("malicious", 0), tpr.get("total", 0)
        if total:
            status = (
                f"{mal}/{total} vendors flagged malicious"
                if mal
                else f"Clean ({total} vendors checked)"
            )
            add_unique("Reputation", status)

    # Top Threats
    threats = [
        t.get("threat_name") for t in data.get("top_threats", [])[:5] if t.get("threat_name")
    ]
    if threats:
        add_unique("Top Threats", ", ".join(threats))

    # Generic Fields (avoid duplication with file data)
    if not sample:
        add_unique("Classification", data.get("classification"))
        add_unique(
            "Risk Score", data.get("riskscore"), lambda x: x is not None, lambda x: f"{x}/10"
        )
        add_unique("Threat Level", data.get("threat_level"))

    # Timestamps
    for field, label in [("first_seen", "First Seen"), ("last_seen", "Last Seen")]:
        value = data.get(field)
        if value:
            formatted = value[:10] if len(str(value)) > 10 else str(value)
            add_unique(label, formatted)

    return "\n".join(parts) if parts else "No summary data available"


def _format_third_party_details(data: Dict) -> str:
    """Format third party reputation details as text.

    Lists vendor detections with their status.
    """
    tpr = data.get("third_party_reputations", {})
    sources = tpr.get("sources", [])

    if not sources:
        return "No third-party reputation data available"

    lines = ["=== Third Party Reputations ==="]

    # Group by detection type
    malicious = []
    suspicious = []
    clean = []

    for src in sources:
        name = src.get("source", "Unknown")
        detection = src.get("detection", "unknown")
        categories = src.get("categories", [])
        cat_str = f" ({', '.join(categories)})" if categories else ""

        if detection == "malicious":
            malicious.append(f"  {name}: MALICIOUS{cat_str}")
        elif detection == "suspicious":
            suspicious.append(f"  {name}: Suspicious{cat_str}")
        else:
            clean.append(f"  {name}: Clean")

    if malicious:
        lines.append("\nMalicious:")
        lines.extend(malicious)

    if suspicious:
        lines.append("\nSuspicious:")
        lines.extend(suspicious)

    # Only show first few clean vendors
    if clean:
        lines.append(f"\nClean: {len(clean)} vendors")

    # Add top threats if present
    top_threats = data.get("top_threats", [])
    if top_threats:
        lines.append("\n=== Top Threats ===")
        for t in top_threats[:5]:
            name = t.get("threat_name", "Unknown")
            score = t.get("risk_score", 0)
            count = t.get("files_count", 0)
            lines.append(f"  {name} (risk: {score}, files: {count})")

    return "\n".join(lines)


def _format_dns_value(dns_type: str, value: str) -> str:
    """Format DNS record type/value into appropriate MISP attribute name."""
    # Map DNS types to MISP attribute types
    type_mapping = {
        "A": "a-record",
        "AAAA": "aaaa-record",
        "MX": "mx-record",
        "CNAME": "cname-record",
        "TXT": "txt-record",
        "NS": "ns-record",
        "SOA": "soa-record",
        "PTR": "ptr-record",
        "SRV": "srv-record",
        "HINFO": "hinfo-record",
        "WKS": "wks-record",
        "MINFO": "minfo-record",
        "MB": "mb-record",
        "MG": "mg-record",
        "MR": "mr-record",
    }

    # Return the mapped attribute type, or default to generic text
    return type_mapping.get(dns_type.upper(), "text")


def introspection() -> Dict[str, Any]:
    """Return module introspection data.

    Called by MISP to discover module capabilities.
    """
    return mispattributes


def version() -> Dict[str, Any]:
    """Return module version info.

    Called by MISP to get module metadata.
    """
    return moduleinfo
