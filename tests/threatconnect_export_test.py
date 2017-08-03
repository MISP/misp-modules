"""Test module for the ThreatConnect Export module"""
import base64
import csv
import io
import json
import os
import unittest
import requests


class TestModules(unittest.TestCase):
    """Unittest module for threat_connect_export.py"""
    def setUp(self):
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"
        self.module = "threat_connect_export"
        input_event_path = "%s/test_files/misp_event.json" % os.path.dirname(os.path.realpath(__file__))
        with open(input_event_path, "r") as ifile:
            self.event = json.load(ifile)

    def test_01_introspection(self):
        """Taken from test.py"""
        try:
            response = requests.get(self.url + "modules")
            modules = [module["name"] for module in response.json()]
            assert self.module in modules
        finally:
            response.connection.close()

    def test_02_export(self):
        """Test an event export"""
        test_source = "Test Export"
        query = {
            "module": self.module,
            "data": [self.event],
            "config": {
                "Default_Source": test_source
            }
        }

        try:
            response = requests.post(self.url + "query", headers=self.headers, data=json.dumps(query))
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

if __name__ == "__main__":
    unittest.main()
