#!/usr/bin/env python3
# -*- coding: utf-8 -*
import requests
mispUrlLocal = 'http://misp.local/modules/queryEnrichment/'
mispKeyLocal = 'xxxxxxxx'

def printResult(p):
    session = requests.Session()
    session.headers.update({
        'Authorization': mispKeyLocal,
        'Accept': 'application/json',
        'content-type': 'application/json'})
    r = session.post(mispUrlLocal, json=p)
    print(r.text)


def testSimpleHash():
    p = {'module':'hashstore',
        'hashs': '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5'
    }
    printResult(p)

def testListHash():
    p = {'module':'hashstore',
        'hashs':[
            '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5',
            '003681a69aecd31b1d8ffd870fc0b91c2d68c46694d98d8c13bdd7ab0620d46e'
        ]}
    printResult(p)


def testSimpleQuick():
    p = {'module':'hashstore',
        'hashs': '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5',
        'quick_search' : True}
    printResult(p)

def testListQuick():
    p = {'module':'hashstore',
        'hashs':[
            '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5',
            '003681a69aecd31b1d8ffd870fc0b91c2d68c46694d98d8c13bdd7ab0620d46e'
        ],
        'quick_search' : True}
    printResult(p)

def testSimpleUuid():
    p = {
        'module':'hashstore',
        'hashs': '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5',
        'return_uuid' : True
    }
    printResult(p)


def testListUuid():
    p = {
        'module':'hashstore',
        'hashs':[
            '0002969c86f26bf044714999910ca15c1397365ff4db9b752078a425b5dac8b5',
            '003681a69aecd31b1d8ffd870fc0b91c2d68c46694d98d8c13bdd7ab0620d46e'
        ],
        'return_uuid' : True
    }
    printResult(p)

def testSimpleValue():
    p = {
        'module':'hashstore',
        'values': '31.210.111.154'
    }
    printResult(p)

def testMutlipleValue():
    p = {
        'module':'hashstore',
        'values': [
            '31.210.111.154',
            'globaldefencetalk.com'
            ]
    }
    printResult(p)

if __name__ == "__main__":
    testSimpleHash()
    testListHash()
    testSimpleQuick()
    testListQuick()
    testSimpleUuid()
    testListUuid()
    testSimpleValue()
    testMutlipleValue()
