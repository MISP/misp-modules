import json
from pathlib import Path
from unittest.mock import patch

from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

import misp_modules
from misp_modules import __main__ as service
from misp_modules.modules.action_mod import irc, signal


class TestMessagingActionsHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        for name, module in (("irc", irc), ("signal", signal)):
            service.MODULES_HANDLERS.update({name: module, f"type:{name}": "action_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_dispatch(self):
        discovered = {
            module.stem
            for kind, module in misp_modules.iterate_modules(Path(misp_modules.__file__).parent / "modules")
            if kind.name == "action_mod"
        }
        assert {"irc", "signal"} <= discovered
        descriptors = {entry["name"]: entry for entry in json.loads(self.fetch("/modules").body)}
        for name, module in (("irc", irc), ("signal", signal)):
            descriptor = descriptors[name]
            assert descriptor["type"] == "action_mod"
            assert descriptor["mispattributes"] == module.introspection()
            assert descriptor["meta"]["config"]["support_filters"] is True
            assert descriptor["meta"]["config"]["blocking"] is False
            assert descriptor["meta"]["config"]["expect_misp_core_format"] is False
            assert module.returns == "boolean"
            with patch.object(module, "create_post", return_value=True) as send:
                response = self.fetch(
                    "/query",
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"module": name, "params": {}, "data": {}}),
                )
            assert response.code == 200 and json.loads(response.body) == {"data": True}
            send.assert_called_once()
