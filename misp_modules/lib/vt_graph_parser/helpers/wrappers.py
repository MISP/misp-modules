"""vt_graph_parser.helpers.wrappers.

This module provides a Python object wrapper for MISP objects.
"""


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
        "filename": "file",
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
        if misp_type.startswith("filename|"):
            label, value = value.split("|")
            misp_type = "filename|X"
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
