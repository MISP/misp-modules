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

    def test_email_attachment_basic(self):
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_unpack(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_password_in_body(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        test_email = helper_create_email({"body":"""The password is infected

        Best,
        "some random malware researcher who thinks he is slick." """})

        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(test_email)}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_password_in_body_sentance(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        test_email = helper_create_email({"body":"""The password is infected.

        Best,
        "some random malware researcher who thinks he is slick." """})

        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(test_email)}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_password_in_html_body(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        # TODO Encrypt baseline attachment with "i like pineapples!!!"
        # TODO Figure out how to set HTML body
        test_email = helper_create_email({"body":"""The password is found in this email.
        It is "i like pineapples!!!".

        Best,
        "some random malware researcher who thinks he is slick." """})
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_password_in_subject(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(bytes(f.read(), 'utf8')),
                               'utf8')}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_passphraise_in_quotes(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        # TODO Encrypt baseline attachment with "i like pineapples!!!"
        test_email = helper_create_email({"body":"""The password is found in this email.
        It is "i like pineapples!!!".

        Best,
        "some random malware researcher who thinks he is slick." """})
        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(test_email)}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_as_malware_passphraise_in_brackets(self):
        raise NotImplementedError("NOT IMPLEMENTED")
        # TODO Encrypt baseline attachment with "i like pineapples!!!"
        test_email = helper_create_email({"body":"""The password is found in this email.
        It is [i like pineapples!!!].

        Best,
        "some random malware researcher who thinks he is slick." """})

        with open("tests/test_attachment.eml", "r") as f:
            data = json.dumps({"module":"email_import",
                    "data":str(base64.b64encode(test_email)}).encode('utf8')
            response = requests.post(self.url + "query", data=data)
            response.connection.close()
            print(response.json())

    def test_email_attachment_unpack_and_as_malware(self):
        raise NotImplementedError("NOT IMPLEMENTED")
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



def helper_create_email(**conf):
    raise NotImplementedError("NOT IMPLEMENTED")
    attachment_name = conf.get("attachment_name", None)
    subject = conf.get("subject", "Hello friend this is a test email")
    subject = conf.get("subject", "Hello friend this is a test email")
    received = conf.get("Received", ["""Received: via dmail-2008.19 for +INBOX;\n\tTue, 3 Feb 2009 19:29:12 -0600 (CST)""","""Received: from abc.luxsci.com ([10.10.10.10])\n\tby xyz.luxsci.com (8.13.7/8.13.7) with\n\tESMTP id n141TCa7022588\n\tfor <test@domain.com>;\n\tTue, 3 Feb 2009 19:29:12 -0600""", """Received: from [192.168.0.3] (verizon.net [44.44.44.44])\n\t(user=test@sender.com mech=PLAIN bits=2)\n\tby abc.luxsci.com (8.13.7/8.13.7) with\n\tESMTP id n141SAfo021855\n\t(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-SHA\n\tbits=256 verify=NOT) for <test@domain.com>;\n\tTue, 3 Feb 2009 19:28:10 -0600"""])
    return_path = conf.get("Return-Path", "Return-Path: evil_spoofer@example.com")








if __name__ == '__main__':
    unittest.main()
