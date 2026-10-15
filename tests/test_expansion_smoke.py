import json
from unittest.mock import Mock, patch

import dns.resolver
import pytest

from misp_modules.modules.expansion import dbl_spamhaus
from tests import test_expansions


@pytest.mark.parametrize(
    "answer",
    ["127.0.1.4", "127.0.1.255", "127.255.255.254", dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout],
)
def test_spamhaus_smoke_accepts_the_module_response_contract(answer):
    case = test_expansions.TestExpansions(methodName="test_dbl_spamhaus")
    case.setUp()

    def post(query):
        payload = dbl_spamhaus.handler(json.dumps(query))
        return Mock(json=lambda: payload)

    with (
        patch.object(dbl_spamhaus.resolver, "resolve") as resolve,
        patch.object(case, "misp_modules_post", side_effect=post),
    ):
        if isinstance(answer, str):
            resolve.return_value = [answer]
        else:
            resolve.side_effect = answer
        case.test_dbl_spamhaus()
    resolve.assert_called_once_with("totalmateria.net.dbl.spamhaus.org", "A")


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "Unexpected module failure"},
        {"results": {"Object": [{"name": "wrong-object"}]}},
        {
            "results": {
                "Object": [
                    {"name": "reputation", "Attribute": [{"object_relation": "list-name", "value": "wrong-list"}]}
                ]
            }
        },
        {"error": "totalmateria.net is not listed on dbl.spamhaus.org.", "results": {}},
    ],
)
def test_spamhaus_smoke_still_rejects_invalid_responses(payload):
    case = test_expansions.TestExpansions(methodName="test_dbl_spamhaus")
    case.setUp()
    with patch.object(case, "misp_modules_post", return_value=Mock(json=lambda: payload)):
        with pytest.raises(AssertionError):
            case.test_dbl_spamhaus()
