import json

import requests
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


def fetchHTML(url):
    r = requests.get(url)
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
    if request.get("url"):
        url = request["url"]
    else:
        return False
    html = fetchHTML(url)
    html = stripUselessTags(html)
    markdown = convertHTML(html)

    r = {"results": [{"types": mispattributes["output"], "values": [str(markdown)]}]}
    return r


def introspection():
    return mispattributes


def version():
    return moduleinfo
