import pytest
from unittest.mock import MagicMock, patch

from misp_modules.modules.expansion import crowdstrike_falcon


def _api(response):
    with patch.object(crowdstrike_falcon, "Intel") as mocked_intel:
        mocked_intel.return_value.query_indicator_entities.return_value = response
        return crowdstrike_falcon.CSIntelAPI(custid="id", custkey="key")


def test_search_indicator_without_body():
    api = _api({"status_code": 200})
    assert api.search_indicator("foo") == {}


def test_search_indicator_without_errors_key():
    api = _api({"status_code": 200, "body": {"resources": []}})
    assert api.search_indicator("foo") == {"resources": []}


def test_search_indicator_raises_on_api_errors():
    api = _api({"status_code": 200, "body": {"errors": ["bad", "worse"]}})
    with pytest.raises(Exception, match=r"API Error: bad \| worse"):
        api.search_indicator("foo")
