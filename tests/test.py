#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests
import base64
import json
import os
import urllib


class TestModules(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"

    def test_introspection(self):
        response = requests.get(self.url + "modules")
        print(response.json())
        response.connection.close()

    def test_cve(self):
        with open('tests/bodycve.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()

    def test_dns(self):
        with open('tests/body.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()
        with open('tests/body_timeout.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()

    def test_stix(self):
        with open("tests/stix.xml", "r") as f:
            data = json.dumps({"module":"stiximport",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf-8'))),
                    "config": {"max_size": "15000"},
                   })

            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_headers(self):
        with open("tests/test_no_attach.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment(self):
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_virustotal(self):
        # This can't actually be tested without disclosing a private
        # API key. This will attempt to run with a .gitignored keyfile
        # and pass if it can't find one

        if not os.path.exists("tests/bodyvirustotal.json"):
          return

        with open("tests/bodyvirustotal.json", "r") as f:
          response = requests.post(self.url + "query", data=f.read()).json()
        assert(response)
        response.connection.close()

if __name__ == '__main__':
    unittest.main()
