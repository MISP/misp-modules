#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests
from urllib.parse import urljoin
import json


class TestExpansions(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"

    def misp_modules_post(self, query):
        return requests.post(urljoin(self.url, "query"), json=query)

    def get_values(self, response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['results'][0]['values']

    def test_cve(self):
        query = {"module": "cve", "vulnerability": "CVE-2010-3333", "config": {"custom_API": "https://cve.circl.lu/api/cve/"}}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith("Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3"))

    def test_dns(self):
        query = {"module": "dns", "hostname": "www.circl.lu", "config": {"nameserver": "8.8.8.8"}}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), ['149.13.33.14'])

    def test_macvendors(self):
        query = {"module": "macvendors", "mac-address": "FC-A1-3E-2A-1C-33"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Samsung Electronics Co.,Ltd')

    def test_haveibeenpwned(self):
        query = {"module": "hibp", "email-src": "info@circl.lu"}
        response = self.misp_modules_post(query)
        to_check = self.get_values(response)
        if to_check == "haveibeenpwned.com API not accessible (HTTP 401)":
            self.skipTest(f"haveibeenpwned blocks travis IPs: {response}")
        self.assertEqual(to_check, 'OK (Not Found)', response)

    def test_greynoise(self):
        query = {"module": "greynoise", "ip-dst": "1.1.1.1"}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).strartswith('{"ip":"1.1.1.1","status":"ok"')

    def test_ipasn(self):
        query = {"module": "ipasn", "ip-dst": "1.1.1.1"}
        response = self.misp_modules_post(query)
        key = list(self.get_values(response)['response'].keys())[0]
        entry = self.get_values(response)['response'][key]['asn']
        self.assertEqual(entry, '13335')

    def test_bgpranking(self):
        query = {"module": "bgpranking", "AS": "13335"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response)['response']['asn_description'], 'CLOUDFLARENET - Cloudflare, Inc., US')
