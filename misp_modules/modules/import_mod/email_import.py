#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import zipfile
import re
from html.parser import HTMLParser
from pymisp.tools import EMailObject, make_binary_objects
try:
    from pymisp.tools import URLObject
except ImportError:
    raise ImportError('Unable to import URLObject, pyfaup missing')
from io import BytesIO
from pathlib import Path


misperrors = {'error': 'Error'}

mispattributes = {'inputSource': ['file'], 'output': ['MISP objects'],
                  'format': 'misp_standard'}

moduleinfo = {'version': '0.2',
              'author': 'Seamus Tuohy, Raphaël Vinot',
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

    # Decode and parse email
    request = json.loads(q)
    # request data is always base 64 byte encoded
    data = base64.b64decode(request["data"])

    email_object = EMailObject(pseudofile=BytesIO(data), attach_original_mail=True, standalone=False)

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
        password_list = get_zip_passwords(email_object.email)

    # Do we extract URL's from the email.
    extract_urls = config.get("extract_urls", None)
    if (extract_urls is not None and extract_urls.lower() in acceptable_config_yes):
        extract_urls = True

    file_objects = []  # All possible file objects
    # Get Attachments
    # Get file names of attachments
    for attachment_name, attachment in email_object.attachments:
        # Create file objects for the attachments
        if not attachment_name:
            attachment_name = 'NameMissing.txt'

        temp_filename = Path(attachment_name)
        zipped_files = ["doc", "docx", "dot", "dotx", "xls", "xlsx", "xlm", "xla",
                        "xlc", "xlt", "xltx", "xlw", "ppt", "pptx", "pps", "ppsx",
                        "pot", "potx", "potx", "sldx", "odt", "ods", "odp", "odg",
                        "odf", "fodt", "fods", "fodp", "fodg", "ott", "uot"]
        # Attempt to unzip the attachment and return its files
        if unzip and temp_filename.suffix[1:] not in zipped_files:
            try:
                unzip_attachement(attachment_name, attachment, email_object, file_objects)
            except RuntimeError:  # File is encrypted with a password
                if zip_pass_crack is True:
                    password = test_zip_passwords(attachment, password_list)
                    if password:
                        unzip_attachement(attachment_name, attachment, email_object, file_objects, password)
                    else:  # Inform the analyst that we could not crack password
                        f_object, main_object, sections = make_binary_objects(pseudofile=attachment, filename=attachment_name, standalone=False)
                        f_object.comment = "Encrypted Zip: Password could not be cracked from message"
                        file_objects.append(f_object)
                        file_objects.append(main_object)
                        file_objects += sections
                        email_object.add_reference(f_object.uuid, 'includes', 'Email attachment')
            except zipfile.BadZipFile:  # Attachment is not a zipfile
                # Just straight add the file
                f_object, main_object, sections = make_binary_objects(pseudofile=attachment, filename=attachment_name, standalone=False)
                file_objects.append(f_object)
                file_objects.append(main_object)
                file_objects += sections
                email_object.add_reference(f_object.uuid, 'includes', 'Email attachment')
        else:
            # Just straight add the file
            f_object, main_object, sections = make_binary_objects(pseudofile=attachment, filename=attachment_name, standalone=False)
            file_objects.append(f_object)
            file_objects.append(main_object)
            file_objects += sections
            email_object.add_reference(f_object.uuid, 'includes', 'Email attachment')

    mail_body = email_object.email.get_body(preferencelist=('html', 'plain'))
    if extract_urls:
        if mail_body:
            charset = mail_body.get_content_charset()
            if mail_body.get_content_type() == 'text/html':
                url_parser = HTMLURLParser()
                url_parser.feed(mail_body.get_payload(decode=True).decode(charset, errors='ignore'))
                urls = url_parser.urls
            else:
                urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', mail_body.get_payload(decode=True).decode(charset, errors='ignore'))
            for url in urls:
                if not url:
                    continue
                url_object = URLObject(url, standalone=False)
                file_objects.append(url_object)
                email_object.add_reference(url_object.uuid, 'includes', 'URL in email body')

    objects = [email_object.to_json()]
    if file_objects:
        objects += [o.to_json() for o in file_objects if o]
    r = {'results': {'Object': [json.loads(o) for o in objects]}}
    return r


def unzip_attachement(filename, data, email_object, file_objects, password=None):
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
    with zipfile.ZipFile(data, "r") as zf:
        if password is not None:
            comment = f'Extracted from {filename} with password "{password}"'
            password = str.encode(password)  # Byte encoded password required
        else:
            comment = f'Extracted from {filename}'
        for zip_file_name in zf.namelist():  # Get all files in the zip file
            with zf.open(zip_file_name, mode='r', pwd=password) as fp:
                file_data = BytesIO(fp.read())
            f_object, main_object, sections = make_binary_objects(pseudofile=file_data,
                                                                  filename=zip_file_name,
                                                                  standalone=False)
            f_object.comment = comment
            file_objects.append(f_object)
            file_objects.append(main_object)
            file_objects += sections
            email_object.add_reference(f_object.uuid, 'includes', 'Email attachment')


def test_zip_passwords(data, test_passwords):
    """Test passwords until one is found to be correct.

    Args:
        data (decoded attachment data): Data object decoded from an e-mail part.
        test_passwords (array): List of strings to test as passwords

    Returns:
        Returns a byte string containing a found password and None if password is not found.

    """
    with zipfile.ZipFile(data, "r") as zf:
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
    body = []
    for part in message.walk():
        charset = part.get_content_charset()
        if not charset:
            charset = "utf-8"
        if part.get_content_type() == 'text/plain':
            body.append(part.get_payload(decode=True).decode(charset, errors='ignore'))
        elif part.get_content_type() == 'text/html':
            html_parser = HTMLTextParser()
            payload = part.get_payload(decode=True)
            if payload:
                html_parser.feed(payload.decode(charset, errors='ignore'))
                for text in html_parser.text_data:
                    body.append(text)
    raw_text = "\n".join(body).strip()

    # Add subject to text corpus to parse
    if "Subject" in message:
        subject = " " + message.get('Subject')
        raw_text += subject

    # Grab any strings that are marked off by special chars
    marking_chars = [["\'", "\'"], ['"', '"'], ['[', ']'], ['(', ')']]
    for char_set in marking_chars:
        regex = re.compile(r"""\{0}([^\{1}]*)\{1}""".format(char_set[0], char_set[1]))
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
        if tag == 'img':
            self.urls.append(dict(attrs).get('src'))


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


if __name__ == '__main__':
    with open('tests/test_no_attach.eml', 'r') as email_file:
        handler(q=email_file.read())
