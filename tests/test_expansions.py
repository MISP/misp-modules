#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests
from urllib.parse import urljoin
from base64 import b64encode
import json
import os


class TestExpansions(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"
        self.dirname = os.path.dirname(os.path.realpath(__file__))
        self.sigma_rule = "title: Antivirus Web Shell Detection\r\ndescription: Detects a highly relevant Antivirus alert that reports a web shell\r\ndate: 2018/09/09\r\nmodified: 2019/10/04\r\nauthor: Florian Roth\r\nreferences:\r\n    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/\r\ntags:\r\n    - attack.persistence\r\n    - attack.t1100\r\nlogsource:\r\n    product: antivirus\r\ndetection:\r\n    selection:\r\n        Signature: \r\n            - \"PHP/Backdoor*\"\r\n            - \"JSP/Backdoor*\"\r\n            - \"ASP/Backdoor*\"\r\n            - \"Backdoor.PHP*\"\r\n            - \"Backdoor.JSP*\"\r\n            - \"Backdoor.ASP*\"\r\n            - \"*Webshell*\"\r\n    condition: selection\r\nfields:\r\n    - FileName\r\n    - User\r\nfalsepositives:\r\n    - Unlikely\r\nlevel: critical"
        try:
            with open(f'{self.dirname}/expansion_configs.json', 'rb') as f:
                self.configs = json.loads(f.read().decode())
        except FileNotFoundError:
            self.configs = {}

    def misp_modules_post(self, query):
        return requests.post(urljoin(self.url, "query"), json=query)

    @staticmethod
    def get_attribute(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['results']['Attribute'][0]['type']

    @staticmethod
    def get_data(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['results'][0]['data']

    @staticmethod
    def get_errors(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['error']

    @staticmethod
    def get_object(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data['results']['Object'][0]['name']

    @staticmethod
    def get_values(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        for result in data['results']:
            values = result['values']
            if values:
                return values[0] if isinstance(values, list) else values
        return data['results'][0]['values']

    def test_apiosintds(self):
        query = {'module': 'apiosintds', 'ip-dst': '185.255.79.90'}
        response = self.misp_modules_post(query)
        try:
            self.assertTrue(self.get_values(response).startswith('185.255.79.90 IS listed by OSINT.digitalside.it.'))
        except AssertionError:
            self.assertTrue(self.get_values(response).startswith('185.255.79.90 IS NOT listed by OSINT.digitalside.it.'))

    def test_apivoid(self):
        module_name = "apivoid"
        query = {"module": module_name,
                 "attribute": {"type": "domain",
                               "value": "circl.lu",
                               "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
                 "config": {}}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_object(response), 'dns-record')
            except Exception:
                self.assertTrue(self.get_errors(response).startswith('You do not have enough APIVoid credits'))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'An API key for APIVoid is required.')

    def test_bgpranking(self):
        query = {"module": "bgpranking", "AS": "13335"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response)['response']['asn_description'], 'CLOUDFLARENET, US')

    def test_btc_steroids(self):
        query = {"module": "btc_steroids", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        try:
            self.assertTrue(self.get_values(response).startswith('\n\nAddress:\t1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA\nBalance:\t0.0002126800 BTC (+0.0007482500 BTC / -0.0005355700 BTC)'))

        except Exception:
            self.assertEqual(self.get_values(response), 'Not a valid BTC address, or Balance has changed')

    def test_btc_scam_check(self):
        query = {"module": "btc_scam_check", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '1es14c7qlb5cyhlmuekctxlgc1fv2ti9da fraudolent bitcoin address')

    def test_circl_passivedns(self):
        module_name = "circl_passivedns"
        query = {"module": module_name,
                 "attribute": {"type": "domain",
                               "value": "circl.lu",
                               "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
                 "config": {}}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_object(response), 'passive-dns')
            except Exception:
                self.assertTrue(self.get_errors(response).startswith('There is an authentication error'))
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith('CIRCL Passive DNS authentication is missing.'))

    def test_circl_passivessl(self):
        module_name = "circl_passivessl"
        query = {"module": module_name,
                 "attribute": {"type": "ip-dst",
                               "value": "149.13.33.14",
                               "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
                 "config": {}}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_object(response), 'x509')
            except Exception:
                self.assertTrue(self.get_errors(response).startswith('There is an authentication error'))
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith('CIRCL Passive SSL authentication is missing.'))

    def test_countrycode(self):
        query = {"module": "countrycode", "domain": "www.circl.lu"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), 'Luxembourg')
        except Exception:
            results = ('http://www.geognos.com/api/en/countries/info/all.json not reachable', 'Unknown',
                       'Not able to get the countrycode references from http://www.geognos.com/api/en/countries/info/all.json')
            self.assertIn(self.get_values(response), results)

    def test_cve(self):
        query = {"module": "cve", "vulnerability": "CVE-2010-4444", "config": {"custom_API": "https://cve.circl.lu/api/cve/"}}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith("Unspecified vulnerability in Oracle Sun Java System Access Manager"))

    def test_cve_advanced(self):
        query = {"module": "cve_advanced",
                 "attribute": {"type": "vulnerability",
                               "value": "CVE-2010-4444",
                               "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
                 "config": {}}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_object(response), 'vulnerability')
        except Exception:
            print(self.get_errors(response))

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
        self.assertEqual(self.get_values(response), '149.13.33.14')

    def test_docx(self):
        filename = 'test.docx'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "docx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '\nThis is an basic test docx file. ')

    def test_farsight_passivedns(self):
        module_name = 'farsight_passivedns'
        if module_name in self.configs:
            query_types = ('domain', 'ip-src')
            query_values = ('google.com', '8.8.8.8')
            results = ('mail.casadostemperos.com.br', 'outmail.wphf.at')
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name, query_type: query_value, 'config': self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertIn(result, self.get_values(response))
                except Exception:
                    self.assertTrue(self.get_errors(response).startwith('Something went wrong'))
        else:
            query = {"module": module_name, "ip-src": "8.8.8.8"}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Farsight DNSDB apikey is missing')

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
        value = self.get_values(response)
        if value != 'GreyNoise API not accessible (HTTP 429)':
            self.assertTrue(value.startswith('{"ip":"1.1.1.1","status":"ok"'))

    def test_ipasn(self):
        query = {"module": "ipasn",
                 "attribute": {"type": "ip-src",
                               "value": "149.13.33.14",
                               "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"}}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_object(response), 'asn')

    def test_macaddess_io(self):
        module_name = 'macaddress_io'
        query = {"module": module_name, "mac-address": "44:38:39:ff:ef:57"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response)['Valid MAC address'], 'True')
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Authorization required')

    def test_macvendors(self):
        query = {"module": "macvendors", "mac-address": "FC-A1-3E-2A-1C-33"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Samsung Electronics Co.,Ltd')

    def test_ocr(self):
        filename = 'misp-logo.png'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "ocr_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Threat Sharing')

    def test_ods(self):
        filename = 'test.ods'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "ods_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '\n   column_0\n0  ods test')

    def test_odt(self):
        filename = 'test.odt'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "odt_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'odt test')

    def test_onyphe(self):
        module_name = "onyphe"
        query = {"module": module_name, "ip-src": "8.8.8.8"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertTrue(self.get_values(response).startswith('https://pastebin.com/raw/'))
            except Exception:
                self.assertEqual(self.get_errors(response), 'no more credits')
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Onyphe authentication is missing')

    def test_onyphe_full(self):
        module_name = "onyphe_full"
        query = {"module": module_name, "ip-src": "8.8.8.8"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_values(response), '37.7510,-97.8220')
            except Exception:
                self.assertTrue(self.get_errors(response).startswith('Error '))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Onyphe authentication is missing')

    def test_otx(self):
        query_types = ('domain', 'ip-src', 'md5')
        query_values = ('circl.lu', '8.8.8.8', '616eff3e9a7575ae73821b4668d2801c')
        results = (('149.13.33.14', '149.13.33.17', '6f9814ba70e68c3bce16d253e8d8f86e04a21a2b4172a0f7631040096ba2c47a'),
                   'ffc2595aefa80b61621023252b5f0ccb22b6e31d7f1640913cd8ff74ddbd8b41',
                   '8.8.8.8')
        for query_type, query_value, result in zip(query_types, query_values, results):
            query = {"module": "otx", query_type: query_value, "config": {"apikey": "1"}}
            response = self.misp_modules_post(query)
            try:
                self.assertIn(self.get_values(response), result)
            except KeyError:
                # Empty results, which in this case comes from a connection error
                continue

    def test_passivetotal(self):
        module_name = "passivetotal"
        query = {"module": module_name, "ip-src": "149.13.33.14", "config": {}}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_values(response), 'circl.lu')
            except Exception:
                self.assertIn(self.get_errors(response), ('We hit an error, time to bail!', 'API quota exceeded.'))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Configuration is missing from the request.')

    def test_pdf(self):
        filename = 'test.pdf'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "pdf_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Pdf test')

    def test_pptx(self):
        filename = 'test.pptx'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "pptx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '\npptx test\n')

    def test_qrcode(self):
        filename = 'qrcode.jpeg'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "qrcode", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '1GXZ6v7FZzYBEnoRaG77SJxhu7QkvQmFuh')

    def test_ransomcoindb(self):
        query = {"module": "ransomcoindb",
                 "attributes": {"type": "btc",
                                "value": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA",
                                "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"}}
        if 'ransomcoindb' not in self.configs:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Ransomcoindb API key is missing")

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
        self.assertEqual(self.get_values(response), 'dns.google.')

    def test_securitytrails(self):
        module_name = "securitytrails"
        query_types = ('ip-src', 'domain')
        query_values = ('149.13.33.14', 'circl.lu')
        results = ('circl.lu', 'ns4.eurodns.com')
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name, query_type: query_value, "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_values(response), result)
                except Exception:
                    self.assertTrue(self.get_errors(response).startswith("You've exceeded the usage limits for your account."))
        else:
            query = {"module": module_name, query_values[0]: query_types[0]}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'SecurityTrails authentication is missing')

    def test_shodan(self):
        module_name = "shodan"
        query = {"module": module_name, "ip-src": "149.13.33.14"}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertIn("circl.lu", self.get_values(response))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Shodan authentication is missing')

    def test_sigma_queries(self):
        query = {"module": "sigma_queries", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response)['kibana'].startswith('[\n  {\n    "_id": "Antivirus-Web-Shell-Detection"'))

    def test_sigma_syntax(self):
        query = {"module": "sigma_syntax_validator", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith('Syntax valid:'))

    def test_sourcecache(self):
        input_value = "https://www.misp-project.org/feeds/"
        query = {"module": "sourcecache", "link": input_value}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), input_value)
        self.assertTrue(self.get_data(response).startswith('PCFET0NUWVBFIEhUTUw+CjwhLS0KCUFyY2FuYSBieSBIVE1MN'))

    def test_stix2_pattern_validator(self):
        query = {"module": "stix2_pattern_syntax_validator", "stix2-pattern": "[ipv4-addr:value = '8.8.8.8']"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Syntax valid')

    def test_threatcrowd(self):
        query_types = ('domain', 'ip-src', 'md5', 'whois-registrant-email')
        query_values = ('circl.lu', '149.13.33.4', '616eff3e9a7575ae73821b4668d2801c', 'hostmaster@eurodns.com')
        results = ('149.13.33.14', 'cve.circl.lu', 'devilreturns.com', 'navabi.lu')
        for query_type, query_value, result in zip(query_types, query_values, results):
            query = {"module": "threatcrowd", query_type: query_value}
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response), result)

    def test_threatminer(self):
        query_types = ('domain', 'ip-src', 'md5')
        query_values = ('circl.lu', '149.13.33.4', 'b538dbc6160ef54f755a540e06dc27cd980fc4a12005e90b3627febb44a1a90f')
        results = ('149.13.33.14', 'f6ecb9d5c21defb1f622364a30cb8274f817a1a2', 'http://www.circl.lu/')
        for query_type, query_value, result in zip(query_types, query_values, results):
            query = {"module": "threatminer", query_type: query_value}
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response), result)

    def test_urlhaus(self):
        query_types = ('domain', 'ip-src', 'sha256', 'url')
        query_values = ('www.bestwpdesign.com', '79.118.195.239',
                        'a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3',
                        'http://79.118.195.239:1924/.i')
        results = ('url', 'url', 'virustotal-report', 'virustotal-report')
        for query_type, query_value, result in zip(query_types[:2], query_values[:2], results[:2]):
            query = {"module": "urlhaus",
                     "attribute": {"type": query_type,
                                   "value": query_value,
                                   "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"}}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_attribute(response), result)
        for query_type, query_value, result in zip(query_types[2:], query_values[2:], results[2:]):
            query = {"module": "urlhaus",
                     "attribute": {"type": query_type,
                                   "value": query_value,
                                   "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"}}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_object(response), result)

    def test_urlscan(self):
        module_name = "urlscan"
        query = {"module": module_name, "url": "https://circl.lu/team"}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response), 'circl.lu')
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), 'Urlscan apikey is missing')

    def test_virustotal_public(self):
        module_name = "virustotal_public"
        query_types = ('domain', 'ip-src', 'sha256', 'url')
        query_values = ('circl.lu', '149.13.33.14',
                        'a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3',
                        'http://194.169.88.56:49151/.i')
        results = ('whois', 'asn', 'file', 'virustotal-report')
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name,
                         "attribute": {"type": query_type,
                                       "value": query_value},
                         "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_object(response), result)
                except Exception:
                    self.assertEqual(self.get_errors(response), "VirusTotal request rate limit exceeded.")
        else:
            query = {"module": module_name,
                     "attribute": {"type": query_types[0],
                                   "value": query_values[0]}}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A VirusTotal api key is required for this module.")

    def test_virustotal(self):
        module_name = "virustotal"
        query_types = ('domain', 'ip-src', 'sha256', 'url')
        query_values = ('circl.lu', '149.13.33.14',
                        'a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3',
                        'http://194.169.88.56:49151/.i')
        results = ('domain-ip', 'asn', 'virustotal-report', 'virustotal-report')
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name,
                         "attribute": {"type": query_type,
                                       "value": query_value},
                         "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_object(response), result)
                except Exception:
                    self.assertEqual(self.get_errors(response), "VirusTotal request rate limit exceeded.")
        else:
            query = {"module": module_name,
                     "attribute": {"type": query_types[0],
                                   "value": query_values[0]}}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A VirusTotal api key is required for this module.")

    def test_vulners(self):
        module_name = "vulners"
        query = {"module": module_name, "vulnerability": "CVE-2010-3333"}
        if module_name in self.configs:
            query['config'] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response).endswith('"RTF Stack Buffer Overflow Vulnerability."'))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A Vulners api key is required for this module.")

    def test_wikidata(self):
        query = {"module": "wiki", "text": "Google"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), 'http://www.wikidata.org/entity/Q95')
        except KeyError:
            self.assertEqual(self.get_errors(response), 'Something went wrong, look in the server logs for details')
        except Exception:
            self.assertEqual(self.get_values(response), 'No additional data found on Wikidata')

    def test_xforceexchange(self):
        module_name = "xforceexchange"
        query_types = ('domain', 'ip-src', 'md5', 'url', 'vulnerability')
        query_values = ('mediaget.com', '61.255.239.86', '474b9ccf5ab9d72ca8a333889bbb34f0',
                        'mediaget.com', 'CVE-2014-2601')
        results = ('domain-ip', 'domain-ip', 'url', 'domain-ip', 'vulnerability')
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name,
                         "attribute": {"type": query_type,
                                       "value": query_value,
                                       "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
                         "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                self.assertEqual(self.get_object(response), result)
        else:
            query = {"module": module_name,
                     "attribute": {"type": query_types[0],
                                   "value": query_values[0],
                                   "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"}}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "An API authentication is required (key and password).")

    def test_xlsx(self):
        filename = 'test.xlsx'
        with open(f'{self.dirname}/test_files/{filename}', 'rb') as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "xlsx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), '      header\n0  xlsx test')

    def test_yara_query(self):
        query = {"module": "yara_query", "md5": "b2a5abfeef9e36964281a31e17b57c97"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) == "b2a5abfeef9e36964281a31e17b57c97"\r\n}')

    def test_yara_validator(self):
        query = {"module": "yara_syntax_validator", "yara": 'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) == "b2a5abfeef9e36964281a31e17b57c97"\r\n}'}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), 'Syntax valid')
