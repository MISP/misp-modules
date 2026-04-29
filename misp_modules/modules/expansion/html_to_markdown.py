import json
import socket

import requests
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from markdownify import markdownify

misperrors = {"error": "Error"}
mispattributes = {"input": ["url"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Sami Mokaddem",
    "description": "Expansion module to fetch the html content from an url and convert it into markdown.",
    "module-type": ["expansion"],
    "name": "HTML to Markdown",
    "logo": "",
    "requirements": ["The markdownify python library"],
    "features": (
        "The module take an URL as input and the HTML content is fetched from it. This content is then converted into"
        " markdown that is returned as text."
    ),
    "references": [],
    "input": "URL attribute.",
    "output": "Markdown content converted from the HTML fetched from the url.",
}



BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

def _is_ip_blocked(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in BLOCKED_RANGES)


def _hostname_resolves_to_blocked_ip(hostname: str) -> bool:
    try:
        resolved = socket.getaddrinfo(hostname, None)
        return any(_is_ip_blocked(info[4][0]) for info in resolved)
    except socket.gaierror:
        return True


def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        return not _is_ip_blocked(parsed.hostname)
    except ValueError:
        return not _hostname_resolves_to_blocked_ip(parsed.hostname)

def fetchHTML(url):
    if not is_safe_url(url):
        raise ValueError(f"Blocked URL: {url}")
    r = requests.get(url, timeout=10)
    return r.text

def stripUselessTags(html):
    soup = BeautifulSoup(html, "html.parser")
    toRemove = ["script", "head", "header", "footer", "meta", "link"]
    for tag in soup.find_all(toRemove):
        tag.decompose()
    return str(soup)


def convertHTML(html):
    toStrip = ["a", "img"]
    return markdownify(html, heading_style="ATX", strip=toStrip)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('raw_html'):
        html = request.get('raw_html')
    elif request.get('url'):
        url = request['url']
        html = fetchHTML(url)
    else:
        return False
    html = stripUselessTags(html)
    markdown = convertHTML(html)

    r = {"results": [{"types": mispattributes["output"], "values": [str(markdown)]}]}
    return r


def introspection():
    return mispattributes


def version():
    return moduleinfo
