from unittest.mock import Mock

import pymisp
import pytest
import requests

from misp_modules.modules.expansion._rstcloud import client


@pytest.fixture(params=["rst_resolver_from_config", "_pymisp"])
def connect(request, monkeypatch):
    monkeypatch.setattr(client, "_RESOLVER_CACHE", {})
    monkeypatch.setattr(client, "_PYMISP_CACHE", {})
    return getattr(client, request.param)


@pytest.fixture
def api(monkeypatch):
    def make_client(*args, **kwargs):
        instance = Mock()
        instance.galaxies.return_value = []
        return instance

    factory = Mock(side_effect=make_client)
    monkeypatch.setattr(pymisp, "PyMISP", factory)
    return factory


def test_default_verifies_misp_certificate(connect, api):
    assert connect({"misp_url": "https://misp.example", "misp_key": "key"}) is not None
    api.assert_called_once_with("https://misp.example", "key", ssl=True)


@pytest.mark.parametrize("setting", [False, "false", " False ", "0", 0, "no", "off"])
def test_explicit_verification_opt_out(connect, api, setting):
    connect({"misp_url": "https://misp.example", "misp_key": "key", "misp_verifycert": setting})
    api.assert_called_once_with("https://misp.example", "key", ssl=False)


@pytest.mark.parametrize("setting", [True, "true", "1", None, "", "unexpected"])
def test_empty_or_unrecognized_settings_keep_verification(connect, api, setting):
    connect({"misp_url": "https://misp.example", "misp_key": "key", "misp_verifycert": setting})
    api.assert_called_once_with("https://misp.example", "key", ssl=True)


def test_client_cache_isolates_credentials_and_verification(connect, api):
    config = {"misp_url": "https://misp.example", "misp_key": "first-key", "misp_verifycert": False}
    unverified = connect(config)
    verified = connect({**config, "misp_verifycert": True})
    other_key = connect({**config, "misp_key": "second-key", "misp_verifycert": True})
    assert verified is not unverified
    assert other_key is not verified
    assert connect({**config, "misp_verifycert": "true"}) is verified
    assert api.call_count == 3


def test_certificate_failure_does_not_retry_without_verification(connect, api):
    api.side_effect = requests.exceptions.SSLError("untrusted certificate")
    assert connect({"misp_url": "https://misp.example", "misp_key": "key"}) is None
    api.assert_called_once_with("https://misp.example", "key", ssl=True)
    assert not client._PYMISP_CACHE
    assert not client._RESOLVER_CACHE


def test_missing_credentials_does_not_connect(connect, api):
    assert connect({}) is None
    api.assert_not_called()
