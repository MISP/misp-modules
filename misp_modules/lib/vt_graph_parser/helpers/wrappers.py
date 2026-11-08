"""vt_graph_parser.helpers.wrappers.

This module provides a Python object wrapper for MISP objects.
"""

import re

from misp_modules.lib.vt_graph_parser.errors import GraphImportError


class MispAttribute(object):
    """Python object wrapper for MISP attribute.

    Attributes:
      type (str): VirusTotal node type.
      category (str): MISP attribute category.
      value (str): node id.
      label (str): node name.
      misp_type (str): MISP node type.
    """

    MISP_TYPES_REFERENCE = {
        "hostname": "domain",
        "domain": "domain",
        "ip-src": "ip_address",
        "ip-dst": "ip_address",
        "url": "url",
        "filename|X": "file",
        # A name alone is not a VT file identifier. Keep it as a custom node.
        "filename": "filename",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
        "target-user": "victim",
        "target-email": "email",
    }

    def __init__(self, misp_type, category, value, label=""):
        """Constructor for a MispAttribute.

        Args:
            misp_type (str): MISP type attribute.
            category (str): MISP category attribute.
            value (str): attribute value.
            label (str): attribute label.
        """
        if not isinstance(value, str) or not value.strip():
            raise GraphImportError("Supported MISP attributes must have non-empty string values.")
        hash_type = misp_type.removeprefix("filename|")
        if misp_type.startswith("filename|"):
            if "|" not in value:
                raise GraphImportError("A filename/hash attribute must contain a filename and hash separated by |.")
            label, value = value.rsplit("|", 1)
            if not label:
                raise GraphImportError("A filename/hash attribute must contain a filename.")
            misp_type = "filename|X"
        if hash_type in ("md5", "sha1", "sha256"):
            length = {"md5": 32, "sha1": 40, "sha256": 64}[hash_type]
            if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value):
                raise GraphImportError("A file attribute must contain a valid MD5, SHA-1 or SHA-256 hash.")
            value = value.lower()
        if misp_type == "filename":
            label = value

        self.type = self.MISP_TYPES_REFERENCE.get(misp_type)
        self.category = category
        self.value = value
        self.label = label
        self.misp_type = misp_type

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.value == other.value and self.type == other.type

    def __repr__(self):
        return 'MispAttribute("{type}", "{category}", "{value}")'.format(
            type=self.type, category=self.category, value=self.value
        )
