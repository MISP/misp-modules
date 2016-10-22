#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
from email import message_from_bytes
from email.utils import parseaddr
import re

misperrors = {'error': 'Error'}
userConfig = { }

inputSource = ['file']

moduleinfo = {'version': '0.1',
              'author': 'Seamus Tuohy',
              'description': 'Email import module for MISP',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    results = []

    # Decode and parse email
    request = json.loads(q)
    # request data is always base 64 byte encoded
    data = base64.b64decode(request["data"])
    message = message_from_bytes(data)

    # Extract header information

    # Subject
    results.append({"values": message.get('Subject'),
                    "types": ['email-subject']})

    # Source
    from_addr = message.get('From')
    results.append({"values": parseaddr(from_addr)[1],
                    "types": ['email-src'],
                    "comment": "From: {0}".format(from_addr)})

    return_path = message.get('Return-Path')
    results.append({"values": parseaddr(return_path)[1],
                    "types": ['email-src'],
                    "comment": "Return Path: {0}".format(return_path)})

    # Destinations
    ## Split and sort destination header values
    recipient_headers = ['To', 'Cc', 'Bcc']
    destinations = {}

    for hdr_val in recipient_headers:
        try:
            addrs = message.get(hdr_val).split(',')
            for addr in addrs:
                ## Parse and add destination header values
                parsed_addr = parseaddr(addr)
                results.append({"values": parsed_addr[1],
                                "types":  ["email-dst"],
                                "comment": "{0}: {1}".format(hdr_val,
                                                             addr)})
        except AttributeError:
            continue

    # # TODO add 'email-dst-realname' value
    #         results.append({"values":parsed_addr[1],
    #                         "types":["email-dst-realname"],
    #                        "comment":"{0}: {1}".format(dst_type,
    #                                                    addr)})

    # Targets
    # Get the addresses that received the email.
    # As pulled from the Received header
    received = message.get_all('received')
    email_targets = set()
    for rec in received:
        try:
            email_check = re.search("for\s(.*@.*);", rec).group(1)
            email_check = email_check.strip(' <>')
            email_targets.add(parseaddr(email_check)[1])
        except (AttributeError):
            continue
    for tar in email_targets:
        results.append({"values":  tar,
                        "types":   ["target-email"],
                        "comment": "Extracted from email 'Received' header"})

    ## TODO add 'email-received-path' value
    # received_path = '\n'.join(received)
    # results.append({"values":received_path,
    #                 "types":["email-received-path"]})

    # Attachments
    # Get file names of attachments
    for part in message.walk():
        filename = part.get_filename()
        if filename is not None:
            results.append({"values": filename,
                            "types":  ["email-attachment"]})

    r = {'results': results}
    return r


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

if __name__ == '__main__':
    with open('tests/test_no_attach.eml', 'r') as email_file:
        handler(q=email_file.read())
