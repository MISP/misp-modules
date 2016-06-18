#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests


class TestModules(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}

    def test_introspection(self):
        response = requests.get('http://127.0.0.1:6666/modules')
        print(response.json())

    def test_cve(self):
        with open('tests/bodycve.json', 'r') as f:
            response = requests.post('http://127.0.0.1:6666/query', data=f.read())
            print(response.json())

    def test_dns(self):
        with open('tests/body.json', 'r') as f:
            response = requests.post('http://127.0.0.1:6666/query', data=f.read())
            print(response.json())
