#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import unittest
from base64 import b64encode
from urllib.parse import urljoin

import requests

LiveCI = True


class TestExpansions(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {"Content-Type": "application/json"}
        self.url = "http://127.0.0.1:6666/"
        self.dirname = os.path.dirname(os.path.realpath(__file__))
        self.sigma_rule = (
            "title: Antivirus Web Shell Detection\r\ndescription: Detects a highly relevant Antivirus alert that"
            " reports a web shell\r\ndate: 2018/09/09\r\nmodified: 2019/10/04\r\nauthor: Florian"
            " Roth\r\nreferences:\r\n    -"
            " https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/\r\ntags:\r\n    -"
            " attack.persistence\r\n    - attack.t1100\r\nlogsource:\r\n    product: antivirus\r\ndetection:\r\n   "
            ' selection:\r\n        Signature: \r\n            - "PHP/Backdoor*"\r\n            - "JSP/Backdoor*"\r\n  '
            '          - "ASP/Backdoor*"\r\n            - "Backdoor.PHP*"\r\n            - "Backdoor.JSP*"\r\n         '
            '   - "Backdoor.ASP*"\r\n            - "*Webshell*"\r\n    condition: selection\r\nfields:\r\n    -'
            " FileName\r\n    - User\r\nfalsepositives:\r\n    - Unlikely\r\nlevel: critical"
        )
        try:
            with open(f"{self.dirname}/expansion_configs.json", "rb") as f:
                self.configs = json.loads(f.read().decode())
        except FileNotFoundError:
            self.configs = {}

    def misp_modules_post(self, query):
        return requests.post(urljoin(self.url, "query"), json=query)

    @staticmethod
    def get_attribute_types(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        types = []
        for attribute in data["results"]["Attribute"]:
            types.append(attribute["type"])
        return types

    @staticmethod
    def get_data(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data["results"][0]["data"]

    @staticmethod
    def get_errors(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data["error"]

    @staticmethod
    def get_object_types(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        names = []
        for obj in data["results"]["Object"]:
            names.append(obj["name"])
        return names

    @staticmethod
    def get_first_object_type(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        return data["results"]["Object"][0]["name"]

    @staticmethod
    def get_values(response):
        data = response.json()
        if not isinstance(data, dict):
            print(json.dumps(data, indent=2))
            return data
        if "results" not in data:
            return data
        for result in data["results"]:
            values = result["values"]
            if values:
                return values[0] if isinstance(values, list) else values
        return data["results"][0]["values"]

    def test_introspection(self):
        """checks if all expansion modules are offered through the misp-modules service"""
        try:
            response = requests.get(self.url + "modules")
            modules = [module["name"] for module in response.json()]
            # list modules in the export_mod folder
            export_mod_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "misp_modules", "modules", "expansion"
            )
            module_files = [
                file[:-3] for file in os.listdir(export_mod_path) if file.endswith(".py") if file not in ["__init__.py"]
            ]
            missing = []
            for module in module_files:
                if module not in modules:
                    missing.append(module)
            self.assertEqual(missing, [], f"Missing modules in __init__: {missing}")
        finally:
            response.connection.close()

    def test_apiosintds(self):
        self.skipTest("apiosintds is probably broken")

        query = {"module": "apiosintds", "ip-dst": "10.10.10.10"}
        response = self.misp_modules_post(query)

        try:
            self.assertTrue(self.get_values(response).startswith("IoC 10.10.10.10"))
        except AssertionError:
            self.assertTrue(self.get_values(response).startswith("10.10.10.10 IS NOT listed by OSINT.digitalside.it."))

    def test_apivoid(self):
        module_name = "apivoid"
        query = {
            "module": module_name,
            "attribute": {"type": "domain", "value": "circl.lu", "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
            "config": {},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_first_object_type(response), "dns-record")
            except Exception:
                self.assertTrue(self.get_errors(response).startswith("You do not have enough APIVoid credits"))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "An API key for APIVoid is required.")

    def test_btc_steroids(self):
        if LiveCI:
            return True

        query = {"module": "btc_steroids", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        try:
            self.assertTrue(
                self.get_values(response).startswith(
                    "\n\nAddress:\t1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA\nBalance:\t0.0002126800 BTC (+0.0007482500 BTC /"
                    " -0.0005355700 BTC)"
                )
            )

        except Exception:
            self.assertTrue(self.get_values(response).startswith("Not a valid BTC address"))

    def test_btc_scam_check(self):
        query = {"module": "btc_scam_check", "btc": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "1es14c7qlb5cyhlmuekctxlgc1fv2ti9da fraudolent bitcoin address")

    def test_circl_passivedns(self):
        module_name = "circl_passivedns"
        query = {
            "module": module_name,
            "attribute": {"type": "domain", "value": "circl.lu", "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
            "config": {},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_first_object_type(response), "passive-dns")
            except Exception:
                self.assertTrue(self.get_errors(response).startswith("There is an authentication error"))
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith("CIRCL Passive DNS authentication is missing."))

    def test_circl_passivessl(self):
        module_name = "circl_passivessl"
        query = {
            "module": module_name,
            "attribute": {"type": "ip-dst", "value": "185.194.93.14", "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
            "config": {},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_first_object_type(response), "x509")
            except Exception:
                self.assertTrue(self.get_errors(response).startswith("There is an authentication error"))
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith("CIRCL Passive SSL authentication is missing."))

    def test_countrycode(self):
        query = {"module": "countrycode", "domain": "www.circl.lu"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), "Luxembourg")
        except Exception:
            results = (
                "http://www.geognos.com/api/en/countries/info/all.json not reachable",
                "Unknown",
                "Not able to get the countrycode references from http://www.geognos.com/api/en/countries/info/all.json",
            )
            self.assertIn(self.get_values(response), results)

    def test_cve(self):
        query = {
            "module": "cve",
            "attribute": {
                "type": "vulnerability",
                "value": "CVE-2010-4444",
                "uuid": "82383d84-3016-4d1c-902f-3de0533bfcec",
            },
        }
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_first_object_type(response), "vulnerability")
        except Exception:
            print(self.get_errors(response))

    def test_cve_advanced(self):
        query = {
            "module": "cve_advanced",
            "attribute": {
                "type": "vulnerability",
                "value": "CVE-2010-4444",
                "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d",
            },
            "config": {},
        }
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_first_object_type(response), "vulnerability")
        except Exception:
            print(self.get_errors(response))

    def test_dbl_spamhaus(self):
        query = {"module": "dbl_spamhaus", "domain": "totalmateria.net"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), "totalmateria.net - spam test domain")
        except Exception:
            try:
                self.assertTrue(self.get_values(response).startswith("The DNS query name does not exist:"))
            except Exception:
                self.assertEqual(
                    self.get_errors(response), "Not able to reach dbl.spamhaus.org or something went wrong"
                )

    def test_dns(self):
        query = {"module": "dns", "hostname": "www.circl.lu", "config": {"nameserver": "8.8.8.8"}}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "185.194.93.14")

    def test_docx(self):
        filename = "test.docx"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "docx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "\nThis is an basic test docx file. ")

    def test_censys(self):
        module_name = "censys_enrich"
        query = {"attribute": {"type": "ip-dst", "value": "8.8.8.8", "uuid": ""}, "module": module_name, "config": {}}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)

            if self.configs[module_name].get("api_id") == "<api_id>":
                self.assertTrue(self.get_errors(response).startswith("ERROR: param "))
            else:
                self.assertGreaterEqual(len(response.json().get("results", {}).get("Attribute")), 1)
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith("Please provide config options"))

    def test_farsight_passivedns(self):
        module_name = "farsight_passivedns"
        if module_name in self.configs:
            query_types = ("domain", "ip-src")
            query_values = ("google.com", "8.8.8.8")
            results = ("mail.casadostemperos.com.br", "outmail.wphf.at")
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name, query_type: query_value, "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertIn(result, self.get_values(response))
                except Exception:
                    self.assertTrue(self.get_errors(response).startswith("Something went wrong"))
        else:
            query = {"module": module_name, "ip-src": "8.8.8.8"}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Farsight DNSDB apikey is missing")

    def test_haveibeenpwned(self):
        module_name = "hibp"
        query = {"module": "hibp", "email-src": "info@circl.lu"}
        response = self.misp_modules_post(query)
        if module_name in self.configs:
            to_check = self.get_values(response)
            if to_check == "haveibeenpwned.com API not accessible (HTTP 401)":
                self.skipTest(f"haveibeenpwned blocks travis IPs: {response}")
            self.assertEqual(to_check, "OK (Not Found)", response)
        else:
            self.assertEqual(self.get_errors(response), "Have I Been Pwned authentication is incomplete (no API key)")

    def test_hyasinsight(self):
        module_name = "hyasinsight"
        query = {
            "module": module_name,
            "attribute": {
                "type": "phone-number",
                "value": "+84853620279",
                "uuid": "b698dc2b-94c1-487d-8b65-3114bad5a40c",
            },
            "config": {},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response)["domain"], "tienichphongnet.com")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "HYAS Insight apikey is missing")

    def test_greynoise(self):
        module_name = "greynoise"
        query = {"module": module_name, "ip-dst": "1.1.1.1"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_values(response), "This IP is commonly spoofed in Internet-scan activity")
            except Exception:
                self.assertIn(
                    self.get_errors(response),
                    ("Unauthorized. Please check your API key.", "Too many requests. You've hit the rate-limit."),
                )
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "GreyNoise API Key required, but missing")

    @unittest.skip("Service doesn't work")
    def test_ipasn(self):
        query = {
            "module": "ipasn",
            "attribute": {"type": "ip-src", "value": "149.13.33.14", "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
        }
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_first_object_type(response), "asn")

    def test_ipqs_fraud_and_risk_scoring(self):
        module_name = "ipqs_fraud_and_risk_scoring"
        query = {
            "module": module_name,
            "attribute": {
                "type": "email",
                "value": "noreply@ipqualityscore.com",
                "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d",
            },
            "config": {},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response)["message"], "Success.")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "IPQualityScore apikey is missing")

    def test_macaddess_io(self):
        module_name = "macaddress_io"
        query = {"module": module_name, "mac-address": "44:38:39:ff:ef:57"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response)["Valid MAC address"], "True")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Authorization required")

    def test_macvendors(self):
        query = {"module": "macvendors", "mac-address": "FC-A1-3E-2A-1C-33"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "Samsung Electronics Co.,Ltd")

    def test_ocr(self):
        filename = "misp-logo.png"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "ocr_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response).strip("\n"), "Threat Sharing")

    def test_ods(self):
        filename = "test.ods"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "ods_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "\n   column.0\n0  ods test")

    def test_odt(self):
        filename = "test.odt"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "odt_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "odt test")

    def test_onyphe(self):
        module_name = "onyphe"
        if LiveCI:
            return True
        query = {"module": module_name, "ip-src": "8.8.8.8"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertTrue(self.get_values(response).startswith("https://pastebin.com/raw/"))
            except Exception:
                self.assertEqual(self.get_errors(response), "no more credits")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Onyphe authentication is missing")

    def test_onyphe_full(self):
        module_name = "onyphe_full"
        if LiveCI:
            return True
        query = {"module": module_name, "ip-src": "8.8.8.8"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertEqual(self.get_values(response), "37.7510,-97.8220")
            except Exception:
                self.assertTrue(self.get_errors(response).startswith("Error "))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Onyphe authentication is missing")

    @unittest.skip("Unreliable results")
    def test_otx(self):
        query_types = ("domain", "ip-src", "md5")
        query_values = ("circl.lu", "8.8.8.8", "616eff3e9a7575ae73821b4668d2801c")
        results = (
            ("149.13.33.14", "149.13.33.17", "6f9814ba70e68c3bce16d253e8d8f86e04a21a2b4172a0f7631040096ba2c47a"),
            "ffc2595aefa80b61621023252b5f0ccb22b6e31d7f1640913cd8ff74ddbd8b41",
            "8.8.8.8",
        )
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
        query = {"module": module_name, "ip-src": "185.194.93.14", "config": {}}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            try:
                self.assertIn("www.circl.lu", response.json()["results"][0]["values"])
            except Exception:
                self.assertIn(self.get_errors(response), ("We hit an error, time to bail!", "API quota exceeded."))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Configuration is missing from the request.")

    def test_pdf(self):
        filename = "test.pdf"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "pdf_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertRegex(self.get_values(response), r"^Pdf test")

    def test_pptx(self):
        filename = "test.pptx"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "pptx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "\npptx test\n")

    def test_qrcode(self):
        filename = "qrcode.jpeg"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "qrcode", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "1GXZ6v7FZzYBEnoRaG77SJxhu7QkvQmFuh")

    def test_ransomcoindb(self):
        query = {
            "module": "ransomcoindb",
            "attributes": {
                "type": "btc",
                "value": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA",
                "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d",
            },
        }
        if "ransomcoindb" not in self.configs:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Ransomcoindb API key is missing")

    def test_rbl(self):
        if LiveCI:
            return True
        query = {"module": "rbl", "ip-src": "8.8.8.8"}
        response = self.misp_modules_post(query)
        try:
            self.assertTrue(self.get_values(response).startswith("8.8.8.8.bl.spamcannibal.org"))
        except Exception:
            self.assertEqual(self.get_errors(response), "No data found by querying known RBLs")

    def test_reversedns(self):
        query = {"module": "reversedns", "ip-src": "8.8.8.8"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "dns.google.")

    def test_securitytrails(self):
        module_name = "securitytrails"
        query_types = ("ip-src", "domain")
        query_values = ("149.13.33.14", "circl.lu")
        results = ("circl.lu", "ns4.eurodns.com")
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {"module": module_name, query_type: query_value, "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_values(response), result)
                except Exception:
                    self.assertTrue(
                        self.get_errors(response).startswith("You've exceeded the usage limits for your account.")
                    )
        else:
            query = {"module": module_name, query_values[0]: query_types[0]}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "SecurityTrails authentication is missing")

    def test_shodan(self):
        module_name = "shodan"
        query = {
            "module": module_name,
            "attribute": {"uuid": "a21aae0c-7426-4762-9b79-854314d69059", "type": "ip-src", "value": "149.13.33.14"},
        }
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_first_object_type(response), "ip-api-address")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Shodan authentication is missing")

    def test_sigma_queries(self):
        query = {"module": "sigma_queries", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(
            self.get_values(response)["kibana"].startswith('[\n  {\n    "_id": "Antivirus-Web-Shell-Detection"')
        )

    def test_sigma_syntax(self):
        query = {"module": "sigma_syntax_validator", "sigma": self.sigma_rule}
        response = self.misp_modules_post(query)
        self.assertTrue(self.get_values(response).startswith("Syntax valid:"))

    def test_sourcecache(self):
        input_value = "https://www.misp-project.org/feeds/"
        query = {"module": "sourcecache", "link": input_value}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), input_value)
        self.assertTrue(self.get_data(response))

    def test_stix2_pattern_validator(self):
        query = {"module": "stix2_pattern_syntax_validator", "stix2-pattern": "[ipv4-addr:value = '8.8.8.8']"}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "Syntax valid")

    def test_threatcrowd(self):
        if LiveCI:
            return True
        query_types = ("domain", "ip-src", "md5", "whois-registrant-email")
        query_values = ("circl.lu", "149.13.33.14", "616eff3e9a7575ae73821b4668d2801c", "hostmaster@eurodns.com")
        results = ("149.13.33.4", "cve.circl.lu", "devilreturns.com", "navabi.lu")
        for query_type, query_value, result in zip(query_types, query_values, results):
            query = {"module": "threatcrowd", query_type: query_value}
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response), result)

    def test_crowdstrike(self):
        module_name = "crowdstrike_falcon"
        query = {"attribute": {"type": "sha256", "value": "", "uuid": ""}, "module": module_name, "config": {}}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)

            if self.configs[module_name].get("api_id") == "<api_id>":
                self.assertTrue(self.get_errors(response).startswith("HTTP Error:"))
            else:
                self.assertGreaterEqual(len(response.json().get("results", {}).get("Attribute")), 1)
        else:
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_errors(response).startswith("CrowdStrike apikey is missing"))

    def test_threatminer(self):
        if LiveCI:
            return True
        query_types = ("domain", "ip-src", "md5")
        query_values = ("circl.lu", "149.13.33.4", "b538dbc6160ef54f755a540e06dc27cd980fc4a12005e90b3627febb44a1a90f")
        results = ("149.13.33.14", "f6ecb9d5c21defb1f622364a30cb8274f817a1a2", "http://www.circl.lu/")
        for query_type, query_value, result in zip(query_types, query_values, results):
            query = {"module": "threatminer", query_type: query_value}
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response), result)

    @unittest.skip("Service doesn't work")
    def test_urlhaus(self):
        query_types = ("domain", "ip-src", "sha256", "url")
        query_values = (
            "www.bestwpdesign.com",
            "79.118.195.239",
            "a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3",
            "http://79.118.195.239:1924/.i",
        )
        results = ("url", "url", "file", "virustotal-report")

        for query_type, query_value, result in zip(query_types[:2], query_values[:2], results[:2]):
            query = {
                "module": "urlhaus",
                "attribute": {"type": query_type, "value": query_value, "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
            }
            response = self.misp_modules_post(query)
            print(response.json())
            self.assertIn(result, self.get_attribute_types(response))

        for query_type, query_value, result in zip(query_types[2:], query_values[2:], results[2:]):
            query = {
                "module": "urlhaus",
                "attribute": {"type": query_type, "value": query_value, "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d"},
            }
            response = self.misp_modules_post(query)
            print(response.json())
            self.assertIn(result, self.get_object_types(response))

    def test_urlscan(self):
        module_name = "urlscan"
        query = {"module": module_name, "url": "https://circl.lu/team"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_values(response), "circl.lu")
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "Urlscan apikey is missing")

    def test_virustotal_public(self):
        module_name = "virustotal_public"
        attributes = (
            {"uuid": "ffea0594-355a-42fe-9b98-fad28fd248b3", "type": "domain", "value": "circl.lu"},
            {"uuid": "1f3f0f2d-5143-4b05-a0f1-8ac82f51a979", "type": "ip-src", "value": "149.13.33.14"},
            {
                "uuid": "b4be6652-f4ff-4515-ae63-3f016df37e8f",
                "type": "sha256",
                "value": "a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3",
            },
            {"uuid": "6cead544-b683-48cb-b19b-a2561ffa1f51", "type": "url", "value": "http://194.169.88.56:49151/.i"},
        )
        results = ("whois", "asn", "file", "virustotal-report")
        if module_name in self.configs:
            for attribute, result in zip(attributes, results):
                query = {"module": module_name, "attribute": attribute, "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_first_object_type(response), result)
                except Exception:
                    self.assertEqual(self.get_errors(response), "VirusTotal request rate limit exceeded.")
        else:
            query = {"module": module_name, "attribute": attributes[0]}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A VirusTotal api key is required for this module.")

    def test_virustotal(self):
        module_name = "virustotal"
        attributes = (
            {"uuid": "ffea0594-355a-42fe-9b98-fad28fd248b3", "type": "domain", "value": "circl.lu"},
            {"uuid": "1f3f0f2d-5143-4b05-a0f1-8ac82f51a979", "type": "ip-src", "value": "149.13.33.14"},
            {
                "uuid": "b4be6652-f4ff-4515-ae63-3f016df37e8f",
                "type": "sha256",
                "value": "a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3",
            },
            {"uuid": "6cead544-b683-48cb-b19b-a2561ffa1f51", "type": "url", "value": "http://194.169.88.56:49151/.i"},
        )
        results = ("domain-ip", "asn", "virustotal-report", "virustotal-report")
        if module_name in self.configs:
            for attribute, result in zip(attributes, results):
                query = {"module": module_name, "attribute": attribute, "config": self.configs[module_name]}
                response = self.misp_modules_post(query)
                try:
                    self.assertEqual(self.get_first_object_type(response), result)
                except Exception:
                    self.assertEqual(self.get_errors(response), "VirusTotal request rate limit exceeded.")
        else:
            query = {"module": module_name, "attribute": attributes[0]}
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A VirusTotal api key is required for this module.")

    def test_vulners(self):
        module_name = "vulners"
        query = {"module": module_name, "vulnerability": "CVE-2010-3333"}
        if module_name in self.configs:
            query["config"] = self.configs[module_name]
            response = self.misp_modules_post(query)
            self.assertTrue(self.get_values(response).endswith('"RTF Stack Buffer Overflow Vulnerability."'))
        else:
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "A Vulners api key is required for this module.")

    def test_wikidata(self):
        query = {"module": "wiki", "text": "Google"}
        response = self.misp_modules_post(query)
        try:
            self.assertEqual(self.get_values(response), "http://www.wikidata.org/entity/Q95")
        except KeyError:
            self.assertEqual(self.get_errors(response), "Something went wrong, look in the server logs for details")
        except Exception:
            self.assertEqual(self.get_values(response), "No additional data found on Wikidata")

    def test_xforceexchange(self):
        module_name = "xforceexchange"
        query_types = ("domain", "ip-src", "md5", "url", "vulnerability")
        query_values = (
            "mediaget.com",
            "61.255.239.86",
            "474b9ccf5ab9d72ca8a333889bbb34f0",
            "mediaget.com",
            "CVE-2014-2601",
        )
        results = ("domain-ip", "domain-ip", "url", "domain-ip", "vulnerability")
        if module_name in self.configs:
            for query_type, query_value, result in zip(query_types, query_values, results):
                query = {
                    "module": module_name,
                    "attribute": {
                        "type": query_type,
                        "value": query_value,
                        "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d",
                    },
                    "config": self.configs[module_name],
                }
                response = self.misp_modules_post(query)
                self.assertEqual(self.get_first_object_type(response), result)
        else:
            query = {
                "module": module_name,
                "attribute": {
                    "type": query_types[0],
                    "value": query_values[0],
                    "uuid": "ea89a33b-4ab7-4515-9f02-922a0bee333d",
                },
            }
            response = self.misp_modules_post(query)
            self.assertEqual(self.get_errors(response), "An API authentication is required (key and password).")

    def test_xlsx(self):
        if LiveCI:
            return True
        filename = "test.xlsx"
        with open(f"{self.dirname}/test_files/{filename}", "rb") as f:
            encoded = b64encode(f.read()).decode()
        query = {"module": "xlsx_enrich", "attachment": filename, "data": encoded}
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "      header\n0  xlsx test")

    def test_yara_query(self):
        query = {"module": "yara_query", "md5": "b2a5abfeef9e36964281a31e17b57c97"}
        response = self.misp_modules_post(query)
        expected_result = (
            'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) =='
            ' "b2a5abfeef9e36964281a31e17b57c97"\r\n}'
        )

        self.assertEqual(self.get_values(response), expected_result)

    def test_yara_validator(self):
        query = {
            "module": "yara_syntax_validator",
            "yara": (
                'import "hash"\r\nrule MD5 {\r\n\tcondition:\r\n\t\thash.md5(0, filesize) =='
                ' "b2a5abfeef9e36964281a31e17b57c97"\r\n}'
            ),
        }
        response = self.misp_modules_post(query)
        self.assertEqual(self.get_values(response), "Syntax valid")
