#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='misp-modules',
    version='1.0',
    author='Alexandre Dulaunoy',
    author_email='alexandre.dulaunoy@circl.lu',
    maintainer='Alexandre Dulaunoy',
    url='https://github.com/MISP/misp-modules',
    description='MISP modules are autonomous modules that can be used for expansion and other services in MISP',
    packages=['modules', 'helpers'],
    scripts=['bin/misp-modules.py'],
    test_suite="tests",
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    install_requires=[
        'tornado',
        'dnspython3',
        'requests',
        'urlarchiver',
        'passivetotal',
        'PyPDNS',
        'pypssl',
        'redis',
        'pyeupi',
        'ipasn-redis',
        'asnhistory',
    ]
)
