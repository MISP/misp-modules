#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests
import base64
import json

class TestModules(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"

    def test_introspection(self):
        response = requests.get(self.url + "modules")
        print(response.json())

    def test_cve(self):
        with open('tests/bodycve.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())

    def test_dns(self):
        with open('tests/body.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())

    def test_stix(self):
        with open("tests/stix.xml", "r") as f:
            data = json.dumps({"module":"stiximport",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf-8')), 'utf-8')
                   })
            response = requests.post(self.url + "query", data=data)
            print(response.json())

if __name__ == '__main__':
  unittest.main()
