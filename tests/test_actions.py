import os
import unittest

import requests


class TestActions(unittest.TestCase):
    """Unittest module for action modules"""

    def setUp(self):
        self.headers = {"Content-Type": "application/json"}
        self.url = "http://127.0.0.1:6666/"

    def test_introspection(self):
        """checks if all action modules are offered through the misp-modules service"""
        try:
            response = requests.get(self.url + "modules")
            modules = [module["name"] for module in response.json()]
            # list modules in the export_mod folder
            export_mod_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "misp_modules", "modules", "action_mod"
            )
            module_files = [
                file[:-3] for file in os.listdir(export_mod_path) if file.endswith(".py") if file not in ["__init__.py"]
            ]
            missing = []
            for module in module_files:
                if module not in modules:
                    missing.append(module)
            self.assertEqual(missing, [], f"Missing modules in __init__: {missing}")
        finally:
            response.connection.close()


if __name__ == "__main__":
    unittest.main()
