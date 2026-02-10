"""
MISP Expansion Module: QR Code Decoder (Anti-Quishing)
This module downloads and decodes QR codes from local attachments or remote URLs.
It includes security hardening against SSRF and DoS attacks.
"""

import binascii
import json
import re
import socket
import ipaddress
from urllib.parse import urlparse

# Third-party imports
# pylint: disable=import-error
import requests
import cv2
import numpy as np
from pyzbar import pyzbar
import urllib3

# Suppress SSL warnings for analysis purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Pylint ignores for dynamic libraries like cv2
# pylint: disable=no-member

MISP_ERRORS = {"error": "Error"}

MISP_ATTRIBUTES = {
    "input": ["attachment", "url", "link"],
    "output": ["url", "btc"]
}

MODULE_INFO = {
    "version": "0.3",
    "author": "Sascha Rommelfangen & SSI OpenSource",
    "description": "Decode QR codes from attachments OR remote URLs (Anti-Quishing).",
    "module-type": ["expansion", "hover"],
    "name": "QR Code Decode",
    "requirements": ["cv2", "pyzbar", "requests", "numpy"],
    "input": "A QR code stored as attachment attribute or a remote URL.",
    "output": "The URL or bitcoin address the QR code is pointing to.",
}

DEBUG_MODE = True
DEBUG_PREFIX = "[DEBUG] QR Code module: "
CRYPTOCURRENCIES = ["bitcoin"]
SCHEMAS = ["http://", "https://", "ftp://"]
MODULE_CONFIG = []

# --- SECURITY CONFIGURATION ---
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB limit (Anti-DoS)
TIMEOUT_SECONDS = 10


def is_safe_url(url):
    """
    SSRF Protection: Validates that the URL resolves to a public IP.
    Returns: (bool, message)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        # DNS Resolution to check real IP
        ip_addr_str = socket.gethostbyname(hostname)
        ip_addr = ipaddress.ip_address(ip_addr_str)

        # Block private, loopback, and reserved IPs
        if ip_addr.is_loopback or ip_addr.is_private or ip_addr.is_reserved:
            return False, f"Blocked internal IP: {ip_addr_str}"

        return True, "OK"
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Fail safe: if we can't resolve or parse, we block
        return False, f"DNS Resolution failed: {str(e)}"


def fetch_url_image(target_url):
    """
    Downloads image from URL with security checks (Anti-Cloaking & DoS protection).
    """
    # 1. SSRF Check
    is_safe, msg = is_safe_url(target_url)
    if not is_safe:
        return None, f"Security Block (SSRF Protection): {msg}"

    try:
        # Anti-Cloaking: Simulate mobile User-Agent
        user_agent = (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/15.0 Mobile/15E148 Safari/604.1"
        )
        headers = {'User-Agent': user_agent}

        # 2. Secure Download (Stream + Size Limit)
        # pylint: disable=missing-timeout
        with requests.get(
            target_url,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
            stream=True,
            verify=False
        ) as response:  # nosec
            response.raise_for_status()

            if 'content-length' in response.headers:
                if int(response.headers['content-length']) > MAX_IMAGE_SIZE:
                    return None, 'Image too large (DoS protection).'

            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_IMAGE_SIZE:
                    return None, 'Image too large (DoS protection) - Download aborted.'

        return np.frombuffer(content, np.uint8), None

    except Exception as e:  # pylint: disable=broad-exception-caught
        return None, f"Fetch Error: {str(e)}"


# pylint: disable=too-many-return-statements, too-many-branches
def handler(q=False):
    """
    Main handler function for MISP module.
    """
    if q is False:
        return False

    q = json.loads(q)
    img_array = None
    filename = "unknown"

    # --- CASE 1: URL Handling ---
    if "url" in q or "link" in q:
        target_url = q.get("url", q.get("link"))
        filename = target_url
        img_array, error_msg = fetch_url_image(target_url)
        if error_msg:
            MISP_ERRORS["error"] = error_msg
            if DEBUG_MODE:
                print(DEBUG_PREFIX + error_msg)
            return MISP_ERRORS

    # --- CASE 2: Attachment Handling ---
    elif "attachment" in q:
        filename = q["attachment"]
        try:
            img_array = np.frombuffer(binascii.a2b_base64(q["data"]), np.uint8)
        except Exception:  # pylint: disable=broad-exception-caught
            return {'error': "Attachment error: empty or invalid data."}

    else:
        return {'error': 'Unsupported input. Provide an attachment or a URL.'}

    # --- DECODING ---
    if img_array is None:
        return {'error': 'Failed to process image data.'}

    try:
        image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
        if image is None:
            return {'error': 'Not a valid image file.'}
        barcodes = pyzbar.decode(image)
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {'error': f'CV2/Pyzbar error: {str(e)}'}

    if not barcodes:
        return {'error': 'No QR code found in image.'}

    for item in barcodes:
        try:
            result = item.data.decode()
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Warning: Could not decode barcode data: {e}")
            continue

        if DEBUG_MODE:
            print(DEBUG_PREFIX + result)

        # Bitcoin logic (Legacy support)
        for crypto in CRYPTOCURRENCIES:
            if crypto in result:
                parts = re.split(r"\:|\?", result)
                if len(parts) > 1 and parts[0] in CRYPTOCURRENCIES:
                    return {
                        "results": [{
                            "types": ["btc"],
                            "values": parts[1],
                            "comment": f"BTC found in {filename}"
                        }]
                    }

        # URL/Text Logic
        is_url = any(schema in result for schema in SCHEMAS)
        return {
            "results": [{
                "types": ["url"] if is_url else ["text"],
                "values": result,
                "comment": f"Decoded from {filename}"
            }]
        }

    return {'error': "Analysis finished but no data returned."}


def introspection():
    """Returns the input and output attributes supported by the module."""
    return MISP_ATTRIBUTES


def version():
    """Returns the version and configuration of the module."""
    MODULE_INFO["config"] = MODULE_CONFIG
    return MODULE_INFO
