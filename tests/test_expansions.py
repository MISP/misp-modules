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
        self.sigma_rule = "title: Antivirus Web Shell Detection\r\ndescription: Detects a highly relevant Antivirus alert that reports a web shell\r\ndate: 2018/09/09\r\nmodified: 2019/10/04\r\nauthor: Florian Roth\r\nreferences:\r\n    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/\r\ntags:\r\n    - attack.persistence\r\n    - attack.t1100\r\nlogsource:\r\n    product: antivirus\r\ndetection:\r\n    selection:\r\n        Signature: \r\n            - \"PHP/Backdoor*\"\r\n            - \"JSP/Backdoor*\"\r\n            - \"ASP/Backdoor*\"\r\n            - \"Backdoor.PHP*\"\r\n            - \"Backdoor.JSP*\"\r\n            - \"Backdoor.ASP*\"\r\n            - \"*Webshell*\"\r\n    condition: selection\r\nfields:\r\n    - FileName\r\n    - User\r\nfalsepositives:\r\n    - Unlikely\r\nlevel: critical"

    def misp_modules_post(self, query):
        return requests.post(urljoin(self.url, "query"), json=query)

    def get_errors(self, response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['error']

    def get_values(self, response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['results'][0]['values']

    def test_bgpranking(self):
        query = {"module": "bgpranking", "AS": "13335"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response)['response']['asn_description'], 'CLOUDFLARENET - Cloudflare, Inc., US')

    def test_btc_steroids(self):
        query = {"module": "btc_steroids", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response)[0].startswith('\n\nAddress:\t1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA\nBalance:\t0.0000000000 BTC (+0.0005355700 BTC / -0.0005355700 BTC)'))

    def test_btc_scam_check(self):
        query = {"module": "btc_scam_check", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '1es14c7qlb5cyhlmuekctxlgc1fv2ti9da fraudulent bitcoin address')

    def test_countrycode(self):
        query = {"module": "countrycode", "domain": "www.circl.lu"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), ['Luxembourg'])
        except Exception:
            results = ('http://www.geognos.com/api/en/countries/info/all.json not reachable', 'Unknown',
                       'Not able to get the countrycode references from http://www.geognos.com/api/en/countries/info/all.json')
            self.assertIn(self.get_values(response), results)

    def test_cve(self):
        query = {"module": "cve", "vulnerability": "CVE-2010-3333", "config": {"custom_API": "https://cve.circl.lu/api/cve/"}}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith("Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3"))

    def test_dbl_spamhaus(self):
        query = {"module": "dbl_spamhaus", "domain": "totalmateria.net"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), 'totalmateria.net - spam domain')
        except Exception:
            try:
                self.assertTrue(self.get_values(response).startswith('None of DNS query names exist:'))
            except Exception:
                self.assertEqual(self.get_errors(response), 'Not able to reach dbl.spamhaus.org or something went wrong')

    def test_dns(self):
        query = {"module": "dns", "hostname": "www.circl.lu", "config": {"nameserver": "8.8.8.8"}}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), ['149.13.33.14'])

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
        self.assertTrue(self.get_values(response).startswith('{"ip":"1.1.1.1","status":"ok"'))

    def test_ipasn(self):
        query = {"module": "ipasn", "ip-dst": "1.1.1.1"}
        response = self.misp_modules_post(query)
        key = list(self.get_values(response)['response'].keys())[0]
        entry = self.get_values(response)['response'][key]['asn']
        self.assertEqual(entry, '13335')

    def test_macvendors(self):
        query = {"module": "macvendors", "mac-address": "FC-A1-3E-2A-1C-33"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Samsung Electronics Co.,Ltd')

    def test_rbl(self):
        query = {"module": "rbl", "ip-src": "8.8.8.8"}
        response = self.misp_modules_post(query)
        try:
            self.assertTrue(self.get_values(response).startswith('8.8.8.8.query.senderbase.org: "0-0=1|1=GOOGLE'))
        except Exception:
            self.assertEqual(self.get_errors(response), "No data found by querying known RBLs")

    def test_reversedns(self):
        query = {"module": "reversedns", "ip-src": "8.8.8.8"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), ['dns.google.'])

    def test_sigma_queries(self):
        query = {"module": "sigma_queries", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response)['kibana'].startswith('[\n  {\n    "_id": "Antivirus-Web-Shell-Detection"'))

    def test_sigma_syntax(self):
        query = {"module": "sigma_syntax_validator", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith('Syntax valid:'))

    def test_stix2_pattern_validator(self):
        query = {"module": "stix2_pattern_syntax_validator", "stix2-pattern": "[ipv4-addr:value = '8.8.8.8']"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Syntax valid')

    def test_wikidata(self):
        query = {"module": "wiki", "text": "Google"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), 'http://www.wikidata.org/entity/Q95')
        except KeyError:
            self.assertEqual(self.get_errors(response), 'Something went wrong, look in the server logs for details')
        except Exception:
            self.assertEqual(self.get_values(response), 'No additional data found on Wikidata')

    def test_yara_query(self):
        query = {"module": "yara_query", "md5": "b2a5abfeef9e36964281a31e17b57c97"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) == "b2a5abfeef9e36964281a31e17b57c97"\r\n}')

    def test_yara_validator(self):
        query = {"module": "yara_syntax_validator", "yara": 'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) == "b2a5abfeef9e36964281a31e17b57c97"\r\n}'}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Syntax valid')
