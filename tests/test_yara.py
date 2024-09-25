
import json
import os
import unittest
import sys
try:
    import yara
except (OSError, ImportError):
    sys.exit("yara is missing, use 'pip3 install -I -r REQUIREMENTS' from the root of this repository to install it.")


class TestYara(unittest.TestCase):
    """Unittest module for yara related modules"""
    def setUp(self):
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"
        self.module = "threat_connect_export"
        input_event_path = "%s/test_files/misp_event.json" % os.path.dirname(os.path.realpath(__file__))
        with open(input_event_path, "r") as ifile:
            self.event = json.load(ifile)

    def test_install(self):
        files = ['tests/yara_hash_module_test.yara', 'tests/yara_pe_module_test.yara']

        for file_ in files:
            try:
                rule = yara.compile(file_)
                self.assertIsInstance(rule, yara.Rules)
            except Exception as e:
                raise Exception("Error in file: {} with error: {}".format(file_, e))


if __name__ == "__main__":
    unittest.main()
