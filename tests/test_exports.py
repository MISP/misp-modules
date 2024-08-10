"""Test module for the ThreatConnect Export module"""
import base64
import csv
import io
import json
import os
import unittest
import requests
from urllib.parse import urljoin


class TestExports(unittest.TestCase):
    """Unittest module for export modules"""
    def setUp(self):
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"
        input_event_path = "%s/test_files/misp_event.json" % os.path.dirname(os.path.realpath(__file__))
        with open(input_event_path, "r") as ifile:
            self.event = json.load(ifile)

    def misp_modules_post(self, query):
        return requests.post(urljoin(self.url, "query"), headers=self.headers, json=query)

    @staticmethod
    def get_values(response):
        data = response.json()
        if 'data' in data:
            return base64.b64decode(data['data']).decode("utf-8")

    def test_introspection(self):
        """checks if all export modules are offered through the misp-modules service"""
        try:
            response = requests.get(self.url + "modules")
            modules = [module["name"] for module in response.json()]
            # list modules in the export_mod folder
            export_mod_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'misp_modules', 'modules', "export_mod")
            module_files = [file[:-3] for file in os.listdir(export_mod_path) if file.endswith(".py") if file not in ['__init__.py', 'testexport.py']]
            for module in module_files:
                self.assertIn(module, modules)
        finally:
            response.connection.close()

    def test_threat_connect_export(self):
        """Test an event export"""
        test_source = "Test Export"
        query = {
            "module": 'threat_connect_export',
            "data": [self.event],
            "config": {
                "Default_Source": test_source
            }
        }

        try:
            response = self.misp_modules_post(query)
            data = base64.b64decode(response.json()["data"]).decode("utf-8")
            csvfile = io.StringIO(data)
            reader = csv.DictReader(csvfile)

            values = [field["Value"] for field in reader]
            assert "google.com" in values
            assert "127.0.0.1" in values

            # resetting file pointer to read through again and extract sources
            csvfile.seek(0)
            # use a set comprehension to deduplicate sources
            sources = {field["Source"] for field in reader}
            assert test_source in sources
        finally:
            response.connection.close()

    def test_yara_export(self):
        query = {
            "module": "yara_export",
            "data": [self.event],
        }
        response = self.misp_modules_post(query)
        expected_result = 'rule MISP_e625_MetadataExample\n{\n    meta:\n        my_identifier_1 = "Some string data"\n        my_identifier_2 = 24\n        my_identifier_3 = true\n\n    strings:\n        $my_text_string = "text here"\n        $my_hex_string = { E2 34 A1 C8 23 FB }\n\n    condition:\n        $my_text_string or $my_hex_string\n}\n\n'
        result = self.get_values(response)
        self.assertEqual(result, expected_result)


if __name__ == "__main__":
    unittest.main()
