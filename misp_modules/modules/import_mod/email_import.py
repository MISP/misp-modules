#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import io
import zipfile
import re
from email import message_from_bytes
from email.utils import parseaddr
from email.iterators import typed_subpart_iterator
from html.parser import HTMLParser

misperrors = {'error': 'Error'}
userConfig = {}

inputSource = ['file']

moduleinfo = {'version': '0.1',
              'author': 'Seamus Tuohy',
              'description': 'Email import module for MISP',
              'module-type': ['import']}

# unzip_attachments : Unzip all zip files that are not password protected
# guess_zip_attachment_passwords : This attempts to unzip all password protected zip files using all the strings found in the email body and subject
# extract_urls : This attempts to extract all URL's from text/html parts of the email
moduleconfig = ["unzip_attachments",
                "guess_zip_attachment_passwords",
                "extract_urls"]


def handler(q=False):
    if q is False:
        return False
    results = []

    # Decode and parse email
    request = json.loads(q)
    # request data is always base 64 byte encoded
    data = base64.b64decode(request["data"])
    message = message_from_bytes(data)

    # Extract all header information
    all_headers = ""
    for k, v in message.items():
        all_headers += "{0}: {1}\n".format(k.strip(), v.strip())
    results.append({"values": all_headers, "type": 'email-header'})

    # E-Mail MIME Boundry
    if message.get_boundary():
        results.append({"values": message.get_boundary(), "type": 'email-mime-boundary'})

    # E-Mail Reply To
    if message.get('In-Reply-To'):
        results.append({"values": message.get('In-Reply-To').strip(), "type": 'email-reply-to'})

    # X-Mailer
    if message.get('X-Mailer'):
        results.append({"values": message.get('X-Mailer'), "type": 'email-x-mailer'})

    # Thread Index
    if message.get('Thread-Index'):
        results.append({"values": message.get('Thread-Index'), "type": 'email-thread-index'})

    # Email Message ID
    if message.get('Message-ID'):
        results.append({"values": message.get('Message-ID'), "type": 'email-message-id'})

    # Subject
    if message.get('Subject'):
        results.append({"values": message.get('Subject'), "type": 'email-subject'})

    # Source
    from_addr = message.get('From')
    if from_addr:
        results.append({"values": parseaddr(from_addr)[1], "type": 'email-src', "comment": "From: {0}".format(from_addr)})
        results.append({"values": parseaddr(from_addr)[0], "type": 'email-src-display-name', "comment": "From: {0}".format(from_addr)})

    # Return Path
    return_path = message.get('Return-Path')
    if return_path:
        # E-Mail Source
        results.append({"values": parseaddr(return_path)[1], "type": 'email-src', "comment": "Return Path: {0}".format(return_path)})
        # E-Mail Source Name
        results.append({"values": parseaddr(return_path)[0], "type": 'email-src-display-name', "comment": "Return Path: {0}".format(return_path)})

    # Destinations
    # Split and sort destination header values
    recipient_headers = ['To', 'Cc', 'Bcc']

    for hdr_val in recipient_headers:
        if message.get(hdr_val):
            addrs = message.get(hdr_val).split(',')
            for addr in addrs:
                # Parse and add destination header values
                parsed_addr = parseaddr(addr)
                results.append({"values": parsed_addr[1], "type": "email-dst", "comment": "{0}: {1}".format(hdr_val, addr)})
                results.append({"values": parsed_addr[0], "type": "email-dst-display-name", "comment": "{0}: {1}".format(hdr_val, addr)})

    # Get E-Mail Targets
    # Get the addresses that received the email.
    # As pulled from the Received header
    received = message.get_all('Received')
    if received:
        email_targets = set()
        for rec in received:
            try:
                email_check = re.search("for\s(.*@.*);", rec).group(1)
                email_check = email_check.strip(' <>')
                email_targets.add(parseaddr(email_check)[1])
            except (AttributeError):
                continue
        for tar in email_targets:
            results.append({"values": tar, "type": "target-email", "comment": "Extracted from email 'Received' header"})

    # Check if we were given a configuration
    config = request.get("config", {})
    # Don't be picky about how the user chooses to say yes to these
    acceptable_config_yes = ['y', 'yes', 'true', 't']

    # Do we unzip attachments we find?
    unzip = config.get("unzip_attachments", None)
    if (unzip is not None and unzip.lower() in acceptable_config_yes):
        unzip = True

    # Do we try to find passwords for protected zip files?
    zip_pass_crack = config.get("guess_zip_attachment_passwords", None)
    if (zip_pass_crack is not None and zip_pass_crack.lower() in acceptable_config_yes):
        zip_pass_crack = True
        password_list = None  # Only want to collect password list once

    # Do we extract URL's from the email.
    extract_urls = config.get("extract_urls", None)
    if (extract_urls is not None and extract_urls.lower() in acceptable_config_yes):
        extract_urls = True

    # Get Attachments
    # Get file names of attachments
    for part in message.walk():
        filename = part.get_filename()
        if filename is not None:
            results.append({"values": filename, "type": 'email-attachment'})
            attachment_data = part.get_payload(decode=True)
            # Base attachment data is default
            attachment_files = [{"values": filename, "data": base64.b64encode(attachment_data).decode()}]
            if unzip is True:  # Attempt to unzip the attachment and return its files
                try:
                    attachment_files += get_zipped_contents(filename, attachment_data)
                except RuntimeError:  # File is encrypted with a password
                    if zip_pass_crack is True:
                        if password_list is None:
                            password_list = get_zip_passwords(message)
                        password = test_zip_passwords(attachment_data, password_list)
                        if password is None:  # Inform the analyst that we could not crack password
                            attachment_files[0]['comment'] = "Encrypted Zip: Password could not be cracked from message"
                        else:
                            attachment_files[0]['comment'] = """Original Zipped Attachment with Password {0}""".format(password)
                            attachment_files += get_zipped_contents(filename, attachment_data, password=password)
                except zipfile.BadZipFile:  # Attachment is not a zipfile
                    attachment_files += [{"values": filename, "data": base64.b64encode(attachment_data).decode()}]
            for attch_item in attachment_files:
                attch_item["type"] = 'malware-sample'
                results.append(attch_item)
        else:  # Check email body part for urls
            if (extract_urls is True and part.get_content_type() == 'text/html'):
                url_parser = HTMLURLParser()
                charset = get_charset(part, get_charset(message))
                url_parser.feed(part.get_payload(decode=True).decode(charset))
                urls = url_parser.urls
                for url in urls:
                    results.append({"values": url, "type": "url"})
    r = {'results': results}
    return r


def get_zipped_contents(filename, data, password=None):
    """Extract the contents of a zipfile.

    Args:
        filename (str): A string containing the name of the zip file.
        data (decoded attachment data): Data object decoded from an e-mail part.

    Returns:
        Returns an array containing a dict for each file
        Example Dict {"values":"name_of_file.txt",
                      "data":<Base64 Encoded BytesIO>,
                      "comment":"string here"}

    """
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        unzipped_files = []
        if password is not None:
            password = str.encode(password)  # Byte encoded password required
        for zip_file_name in zf.namelist():  # Get all files in the zip file
            with zf.open(zip_file_name, mode='r', pwd=password) as fp:
                file_data = io.TextIOWrapper(fp).read().encode()
            unzipped_files.append({"values": zip_file_name,
                                   "data": base64.b64encode(file_data).decode(),  # Any password works when not encrypted
                                   "comment": "Extracted from {0}".format(filename)})
    return unzipped_files


def test_zip_passwords(data, test_passwords):
    """Test passwords until one is found to be correct.

    Args:
        data (decoded attachment data): Data object decoded from an e-mail part.
        test_passwords (array): List of strings to test as passwords

    Returns:
        Returns a byte string containing a found password and None if password is not found.

    """
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        firstfile = zf.namelist()[0]
        for pw_test in test_passwords:
            byte_pwd = str.encode(pw_test)
            try:
                zf.open(firstfile, pwd=byte_pwd)
                return pw_test
            except RuntimeError:  # Incorrect Password
                continue
    return None


def get_zip_passwords(message):
    """ Parse message for possible zip password combinations.

    Args:
        message (email.message) Email message object to parse.
    """
    possible_passwords = []
    # Passwords commonly used for malware
    malware_passwords = ["infected", "malware"]
    possible_passwords += malware_passwords
    # Commonly used passwords
    common_passwords = ["123456", "password", "12345678", "qwerty",
                        "abc123", "123456789", "111111", "1234567",
                        "iloveyou", "adobe123", "123123", "sunshine",
                        "1234567890", "letmein", "1234", "monkey",
                        "shadow", "sunshine", "12345", "password1",
                        "princess", "azerty", "trustno1", "000000"]

    possible_passwords += common_passwords

    # Not checking for multi-part message because by having an
    # encrypted zip file it must be multi-part.
    text_parts = [part for part in typed_subpart_iterator(message, 'text', 'plain')]
    html_parts = [part for part in typed_subpart_iterator(message, 'text', 'html')]
    body = []
    # Get full message character set once
    # Language example reference (using python2)
    # http://ginstrom.com/scribbles/2007/11/19/parsing-multilingual-email-with-python/
    message_charset = get_charset(message)
    for part in text_parts:
        charset = get_charset(part, message_charset)
        body.append(part.get_payload(decode=True).decode(charset))
    for part in html_parts:
        charset = get_charset(part, message_charset)
        html_part = part.get_payload(decode=True).decode(charset)
        html_parser = HTMLTextParser()
        html_parser.feed(html_part)
        for text in html_parser.text_data:
            body.append(text)
    raw_text = "\n".join(body).strip()

    # Add subject to text corpus to parse
    subject = " " + message.get('Subject')
    raw_text += subject

    # Grab any strings that are marked off by special chars
    marking_chars = [["\'", "\'"], ['"', '"'], ['[', ']'], ['(', ')']]
    for char_set in marking_chars:
        regex = re.compile("""\{0}([^\{1}]*)\{1}""".format(char_set[0], char_set[1]))
        marked_off = re.findall(regex, raw_text)
        possible_passwords += marked_off

    # Create a list of unique words to test as passwords
    individual_words = re.split(r"\s", raw_text)
    # Also get words with basic punctuation stripped out
    # just in case someone places a password in a proper sentence
    stripped_words = [i.strip('.,;:?!') for i in individual_words]
    unique_words = list(set(individual_words + stripped_words))
    possible_passwords += unique_words

    return possible_passwords


class HTMLTextParser(HTMLParser):
    """ Parse all text and data from HTML strings."""
    def __init__(self, text_data=None):
        HTMLParser.__init__(self)
        if text_data is None:
            self.text_data = []
        else:
            self.text_data = text_data

    def handle_data(self, data):
        self.text_data.append(data)


class HTMLURLParser(HTMLParser):
    """ Parse all href targets from HTML strings."""
    def __init__(self, urls=None):
        HTMLParser.__init__(self)
        if urls is None:
            self.urls = []
        else:
            self.urls = urls

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.urls.append(dict(attrs).get('href'))


def get_charset(message, default="ascii"):
    """Get a message objects charset

    Args:
        message (email.message): Email message object to parse.
        default (string): String containing default charset to return.
    """
    if message.get_content_charset():
        return message.get_content_charset()
    if message.get_charset():
        return message.get_charset()
    return default


def introspection():
    modulesetup = {}
    try:
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
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
