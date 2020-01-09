"""vt_graph_parser.errors.

This module provides custom errors for data importers.
"""


class GraphImportError(Exception):
    pass


class InvalidFileFormatError(Exception):
    pass


class MispEventNotFoundError(Exception):
    pass


class ServerError(Exception):
    pass
