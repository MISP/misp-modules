from unittest.mock import patch

from misp_modules.modules.expansion import yeti


def _make_client():
    attribute = {
        "type": "ip-src",
        "value": "1.2.3.4",
        "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    }
    with patch.object(yeti.pyeti, "YetiApi"):
        return yeti.Yeti("https://yeti.example", "key", attribute)


def test_yeti_handles_observable_without_tags():
    client = _make_client()
    obs_to_add = {"type": "Domain", "value": "example.com"}

    client._Yeti__get_attribute(obs_to_add, "resolves to")

    values = [attr.value for attr in client.misp_event.attributes]
    assert "example.com" in values
