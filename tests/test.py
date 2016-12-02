#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests
import base64
import json
import os

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
        with open('tests/body_timeout.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())

    def test_stix(self):
        with open("tests/stix.xml", "rb") as f:
            content = base64.b64encode(f.read())
            data = json.dumps({"module": "stiximport",
                               "data": content.decode('utf-8'),
                               })
            response = requests.post(self.url + "query", data=data).json()

            print("STIX :: {}".format(response))
            values = [x["values"][0] for x in response["results"]]

            assert("209.239.79.47" in values)
            assert("41.213.121.180" in values)
            assert("eu-society.com" in values)

    def test_virustotal(self):
        # This can't actually be tested without disclosing a private
        # API key. This will attempt to run with a .gitignored keyfile
        # and pass if it can't find one

        if not os.path.exists("tests/bodyvirustotal.json"):
            return

        with open("tests/bodyvirustotal.json", "r") as f:
            response = requests.post(self.url + "query", data=f.read()).json()
        assert(response)

    def test_domaintools(self):
        query = {'config': {'username': 'test_user', 'api_key': 'test_key'}, 'module': 'domaintools', 'domain': 'domaintools.com'}
        response = requests.post(self.url + "query", data=json.dumps(query)).json()
        print(response)


if __name__ == '__main__':
    unittest.main()
