from misp_modules.modules.import_mod.cuckooimport import CuckooParser


def _parser():
    parser = CuckooParser({})
    parser.report = {}
    return parser


def test_add_http_without_network_section():
    """A report without a "network" section must not raise."""
    assert _parser().add_http() is False


def test_add_network_without_network_section():
    parser = _parser()
    assert parser.add_network("tcp") is False
    assert parser.add_network("udp") is False


def test_add_dns_without_network_section():
    assert _parser().add_dns() is False
