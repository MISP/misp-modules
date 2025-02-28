"""vt_graph_parser.helpers.parsers.

This module provides parsers for MISP inputs.
"""

from vt_graph_parser.helpers.wrappers import MispAttribute

MISP_INPUT_ATTR = [
    "hostname",
    "domain",
    "ip-src",
    "ip-dst",
    "md5",
    "sha1",
    "sha256",
    "url",
    "filename|md5",
    "filename",
    "target-user",
    "target-email",
]

VIRUSTOTAL_GRAPH_LINK_PREFIX = "https://www.virustotal.com/graph/"


def _parse_data(attributes, objects):
    """Parse MISP event attributes and objects data.

    Args:
      attributes (dict): dictionary which contains the MISP event attributes data.
      objects (dict): dictionary which contains the MISP event objects data.

    Returns:
      ([MispAttribute], str): MISP attributes and VTGraph link if exists.
        Link defaults to "".
    """
    attributes_data = []
    vt_graph_link = ""

    # Get simple MISP event attributes.
    attributes_data += [attr for attr in attributes if attr.get("type") in MISP_INPUT_ATTR]

    # Get attributes from MISP objects too.
    if objects:
        for object_ in objects:
            object_attrs = object_.get("Attribute", [])
            attributes_data += [attr for attr in object_attrs if attr.get("type") in MISP_INPUT_ATTR]

    # Check if there is any VirusTotal Graph computed in MISP event.
    vt_graph_links = (
        attr
        for attr in attributes
        if attr.get("type") == "link" and attr.get("value", "").startswith(VIRUSTOTAL_GRAPH_LINK_PREFIX)
    )

    # MISP could have more than one VirusTotal Graph, so we will take
    # the last one.
    current_id = 0  # MISP attribute id is the number of the attribute.
    vt_graph_link = ""
    for link in vt_graph_links:
        if int(link.get("id")) > current_id:
            current_id = int(link.get("id"))
            vt_graph_link = link.get("value")

    attributes = [MispAttribute(data["type"], data["category"], data["value"]) for data in attributes_data]
    return (attributes, vt_graph_link.replace(VIRUSTOTAL_GRAPH_LINK_PREFIX, ""))


def parse_pymisp_response(payload):
    """Get event attributes and VirusTotal Graph id from pymisp response.

    Args:
      payload (dict): dictionary which contains pymisp response.

    Returns:
      ([MispAttribute], str): MISP attributes and VTGraph link if exists.
        Link defaults to "".
    """
    event_attrs = payload.get("Attribute", [])
    objects = payload.get("Object")
    return _parse_data(event_attrs, objects)
