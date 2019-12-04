#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests
import base64
import json
import os
import io
import re
import zipfile
from hashlib import sha256
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

class TestModules(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.headers = {'Content-Type': 'application/json'}
        self.url = "http://127.0.0.1:6666/"

    def test_introspection(self):
        response = requests.get(self.url + "modules")
        print(response.json())
        response.connection.close()

    def test_cve(self):
        with open('tests/bodycve.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()

    def test_dns(self):
        with open('tests/body.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()
        with open('tests/body_timeout.json', 'r') as f:
            response = requests.post(self.url + "query", data=f.read())
            print(response.json())
            response.connection.close()

    def test_openioc(self):
        with open("tests/openioc.xml", "rb") as f:
            content = base64.b64encode(f.read())
            data = json.dumps({"module": "openiocimport",
                               "data": content.decode(),
                               })
            response = requests.post(self.url + "query", data=data).json()
            print(response)

            print("OpenIOC :: {}".format(response))
            values = [x["values"][0] for x in response["results"]]
            assert("mrxcls.sys" in values)
            assert("mdmcpq3.PNF" in values)

    @unittest.skip("Need Rewrite")
    def test_email_headers(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        results = response.json()['results']
        values = [x["values"] for x in results]
        types = {}
        for i in results:
            types.setdefault(i["type"], 0)
            types[i["type"]] += 1
        # Check that there are the appropriate number of items
        # Check that all the items were correct
        self.assertEqual(types['target-email'], 1)
        self.assertIn('test@domain.com', values)
        self.assertEqual(types['email-dst-display-name'], 4)
        self.assertIn('Last One', values)
        self.assertIn('Other Friend', values)
        self.assertIn('Second Person', values)
        self.assertIn('Testy Testerson', values)
        self.assertEqual(types['email-dst'], 4)
        self.assertIn('test@domain.com', values)
        self.assertIn('second@domain.com', values)
        self.assertIn('other@friend.net', values)
        self.assertIn('last_one@finally.com', values)
        self.assertEqual(types['email-src-display-name'], 2)
        self.assertIn("Innocent Person", values)
        self.assertEqual(types['email-src'], 2)
        self.assertIn("evil_spoofer@example.com", values)
        self.assertIn("IgnoreMeImInnocent@sender.com", values)
        self.assertEqual(types['email-thread-index'], 1)
        self.assertIn('AQHSR8Us3H3SoaY1oUy9AAwZfMF922bnA9GAgAAi9s4AAGvxAA==', values)
        self.assertEqual(types['email-message-id'], 1)
        self.assertIn("<4988EF2D.40804@example.com>", values)
        self.assertEqual(types['email-subject'], 1)
        self.assertIn("Example Message", values)
        self.assertEqual(types['email-header'], 1)
        self.assertEqual(types['email-x-mailer'], 1)
        self.assertIn("mlx 5.1.7", values)
        self.assertEqual(types['email-reply-to'], 1)
        self.assertIn("<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>", values)

    @unittest.skip("Need Rewrite")
    def test_email_attachment_basic(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/EICAR.com", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'com')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()['results']]
        self.assertIn('EICAR.com', values)
        for i in response.json()['results']:
            if i["type"] == 'email-attachment':
                self.assertEqual(i["values"], "EICAR.com")
            if i['type'] == 'malware-sample':
                attch_data = base64.b64decode(i["data"])
                self.assertEqual(attch_data, b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_attachment_unpack(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/EICAR.com.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        self.assertIn('EICAR.com.zip', values)
        for i in response.json()['results']:
            if i['type'] == 'malware-sample' and i["values"] == 'EICAR.com.zip':
                with zipfile.ZipFile(io.BytesIO(base64.b64decode(i["data"])), 'r') as zf:
                    with zf.open("EICAR.com") as ec:
                        attch_data = ec.read()
                self.assertEqual(attch_data,
                                 b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')
            if i['type'] == 'malware-sample' and i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"])
                self.assertEqual(attch_data,
                                 b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')


    @unittest.skip("Need Rewrite")
    def test_email_dont_unpack_compressed_doc_attachments(self):
        """Ensures that compressed
        """
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/test_files/test.docx", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="test.docx")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('test.docx', values)
        types = {}
        for i in response.json()['results']:
            types.setdefault(i["type"], 0)
            types[i["type"]] += 1
        # Check that there is only one attachment in the bundle
        self.assertEqual(types['malware-sample'], 1)
        for i in response.json()['results']:
            if i['type'] == 'malware-sample' and i["values"] == 'test.docx':
                attch_data = base64.b64decode(i["data"])
                filesum = sha256()
                filesum.update(attch_data)
                self.assertEqual(filesum.hexdigest(),
                                 '098da5381a90d4a51e6b844c18a0fecf2e364813c2f8b317cfdc51c21f2506a5')

    @unittest.skip("Need Rewrite")
    def test_email_attachment_unpack_with_password(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": 'true',
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/infected.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        self.assertIn('EICAR.com.zip', values)
        for i in response.json()['results']:
            if i['type'] == 'malware-sample' and i["values"] == 'EICAR.com.zip':
                with zipfile.ZipFile(io.BytesIO(base64.b64decode(i["data"])), 'r') as zf:
                    # Make sure password was set and still in place
                    self.assertRaises(RuntimeError, zf.open, "EICAR.com")
            if i['type'] == 'malware-sample' and i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"])
                self.assertEqual(attch_data,
                                 b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_attachment_password_in_body(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": 'true',
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a -> STRINGS <- test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/short_password.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        for i in response.json()['results']:
            if i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"]).decode()
                self.assertEqual(attch_data,
                                 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_attachment_password_in_body_quotes(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": 'true',
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail
        the password is "a long password".

        That is all.
        """
        message.attach(MIMEText(text, 'plain'))
        with open("tests/longer_password.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        for i in response.json()['results']:
            # Check that it could be extracted.
            if i['type'] == 'malware-sample' and i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"]).decode()
                self.assertEqual(attch_data,
                                 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_attachment_password_in_html_body(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": 'true',
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail
        the password is NOT "this string".

        That is all.
        """
        html = """\
<html>
  <head></head>
  <body>
    <p>Hi!<br>
       This is the real password?<br>
       It is "a long password".
    </p>
  </body>
</html>
"""
        message.attach(MIMEText(text, 'plain'))
        message.attach(MIMEText(html, 'html'))
        with open("tests/longer_password.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        for i in response.json()['results']:
            # Check that it could be extracted.
            if i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"]).decode()
                self.assertEqual(attch_data,
                                 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_body_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        filenames = os.listdir("tests/test_files/encodings")
        for fn in filenames:
            message = get_base_email()
            encoding = os.path.splitext(fn)
            with open("tests/test_files/encodings/{0}".format(fn), "r", encoding=encoding[0]) as fp:
                # Encoding is used as the name of the file
                text = fp.read()
                message.attach(MIMEText(text, 'html', encoding[0]))
                query['data'] = decode_email(message)
                data = json.dumps(query)
                response = requests.post(self.url + "query", data=data).json()
                self.assertNotIn('error', response, response.get('error', ""))
                self.assertIn('results', response, "No server results found.")


    @unittest.skip("Need Rewrite")
    def test_email_header_proper_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        filenames = os.listdir("tests/test_files/encodings")
        for encoding in ['utf-8', 'utf-16', 'utf-32']:
            message = get_base_email()
            text = """I am a test e-mail
            the password is NOT "this string".
            That is all.
            """
            message.attach(MIMEText(text, 'plain'))
            for hdr, hdr_val in message.items():
                msg = message
                encoded_header = hdr_val.encode(encoding)
                msg.replace_header(hdr, Header(encoded_header, encoding))
                query['data'] = decode_email(msg)
                data = json.dumps(query)
                response = requests.post(self.url + "query", data=data)
                results = response.json()['results']
                values = []
                for x in results:
                    # Remove BOM from UTF-16 strings
                    if re.search('\ufeff', x["values"]):
                        values.append(re.sub('\ufeff', "", x["values"]))
                    else:
                        values.append(x["values"])
                types = {}
                for i in results:
                    types.setdefault(i["type"], 0)
                    types[i["type"]] += 1
                # Check that all the items were correct
                self.assertEqual(types['target-email'], 1)
                self.assertIn('test@domain.com', values)
                self.assertEqual(types['email-dst-display-name'], 4)
                self.assertIn('Last One', values)
                self.assertIn('Other Friend', values)
                self.assertIn('Second Person', values)
                self.assertIn('Testy Testerson', values)
                self.assertEqual(types['email-dst'], 4)
                self.assertIn('test@domain.com', values)
                self.assertIn('second@domain.com', values)
                self.assertIn('other@friend.net', values)
                self.assertIn('last_one@finally.com', values)
                self.assertEqual(types['email-src-display-name'], 2)
                self.assertIn("Innocent Person", values)
                self.assertEqual(types['email-src'], 2)
                self.assertIn("evil_spoofer@example.com", values)
                self.assertIn("IgnoreMeImInnocent@sender.com", values)
                self.assertEqual(types['email-thread-index'], 1)
                self.assertIn('AQHSR8Us3H3SoaY1oUy9AAwZfMF922bnA9GAgAAi9s4AAGvxAA==', values)
                self.assertEqual(types['email-message-id'], 1)
                self.assertIn("<4988EF2D.40804@example.com>", values)
                self.assertEqual(types['email-subject'], 1)
                self.assertIn("Example Message", values)
                self.assertEqual(types['email-header'], 1)
                self.assertEqual(types['email-x-mailer'], 1)
                self.assertIn("mlx 5.1.7", values)
                self.assertEqual(types['email-reply-to'], 1)
                self.assertIn("<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>", values)

                self.assertIn("<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>", values)

    @unittest.skip("Need Rewrite")
    def test_email_header_malformed_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        filenames = os.listdir("tests/test_files/encodings")
        for encoding in ['utf-8', 'utf-16', 'utf-32']:
            message = get_base_email()
            text = """I am a test e-mail
            the password is NOT "this string".
            That is all.
            """
            message.attach(MIMEText(text, 'plain'))
            for hdr, hdr_val in message.items():
                msg = message
                encoded_header = hdr_val.encode(encoding)
                pat = re.compile(hdr_val.encode())
                message_bytes = pat.sub(encoded_header, msg.as_bytes())
                message64 = base64.b64encode(message_bytes).decode()
                query['data'] = message64

                data = json.dumps(query)
                response = requests.post(self.url + "query", data=data)
                results = response.json()['results']
                values = []
                for x in results:
                    # Remove BOM from UTF-16 strings
                    if re.search('\ufeff', x["values"]):
                        values.append(re.sub('\ufeff', "", x["values"]))
                    else:
                        values.append(x["values"])
                types = {}
                for i in results:
                    types.setdefault(i["type"], 0)
                    types[i["type"]] += 1
                # Check that all the items were correct
                self.assertEqual(types['target-email'], 1)
                self.assertIn('test@domain.com', values)
                self.assertEqual(types['email-dst-display-name'], 4)
                self.assertIn('Last One', values)
                self.assertIn('Other Friend', values)
                self.assertIn('Second Person', values)
                self.assertIn('Testy Testerson', values)
                self.assertEqual(types['email-dst'], 4)
                self.assertIn('test@domain.com', values)
                self.assertIn('second@domain.com', values)
                self.assertIn('other@friend.net', values)
                self.assertIn('last_one@finally.com', values)
                self.assertEqual(types['email-src-display-name'], 2)
                self.assertIn("Innocent Person", values)
                self.assertEqual(types['email-src'], 2)
                self.assertIn("evil_spoofer@example.com", values)
                self.assertIn("IgnoreMeImInnocent@sender.com", values)
                self.assertEqual(types['email-thread-index'], 1)
                self.assertIn('AQHSR8Us3H3SoaY1oUy9AAwZfMF922bnA9GAgAAi9s4AAGvxAA==', values)
                self.assertEqual(types['email-message-id'], 1)
                self.assertIn("<4988EF2D.40804@example.com>", values)
                self.assertEqual(types['email-subject'], 1)
                self.assertIn("Example Message", values)
                self.assertEqual(types['email-header'], 1)
                self.assertEqual(types['email-x-mailer'], 1)
                self.assertIn("mlx 5.1.7", values)
                self.assertEqual(types['email-reply-to'], 1)
                self.assertIn("<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>", values)

                self.assertIn("<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>", values)

    @unittest.skip("Need Rewrite")
    def test_email_header_CJK_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        # filenames = os.listdir("tests/test_files/encodings")
        # for encoding in ['utf-8', 'utf-16', 'utf-32']:
        message = get_base_email()
        text = """I am a test e-mail
        the password is NOT "this string".
        That is all.
        """
        message.attach(MIMEText(text, 'plain'))
        japanese_charset = "ビット及び8ビットの2バイト情報交換用符号化拡張漢字集合"
        jisx213 = Header(japanese_charset, 'euc_jisx0213')
        message.replace_header("Subject", jisx213)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        # Parse Response
        RFC_format = '=?euc_jisx0213?b?pdOlw6XItdqk0zil06XDpcikzjKl0KWkpci+8MrzuPK0uc3RyeS55rK9s8jEpbTBu/q9uLnn?='
        for i in response.json()['results']:
            if i['type'] == 'email-subject':
                RFC_encoding_error = "The subject was not decoded from RFC2047 format."
                self.assertNotEqual(RFC_format, i['values'], RFC_encoding_error)
                self.assertEqual(japanese_charset, i['values'], "Subject not properly decoded")

    @unittest.skip("Need Rewrite")
    def test_email_malformed_header_CJK_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        # filenames = os.listdir("tests/test_files/encodings")
        # for encoding in ['utf-8', 'utf-16', 'utf-32']:
        message = get_base_email()
        text = """I am a test e-mail
        the password is NOT "this string".
        That is all.
        """
        message.attach(MIMEText(text, 'plain'))
        japanese_charset = "ビット及び8ビットの2バイト情報交換用符号化拡張漢字集合"
        japanese_bytes = japanese_charset.encode()
        message.replace_header('Subject', "{{REPLACE}}")
        pat = re.compile(b'{{REPLACE}}')
        message_bytes = pat.sub(japanese_bytes, message.as_bytes())
        message64 = base64.b64encode(message_bytes).decode()
        query['data'] = message64
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        # Parse Response
        RFC_format = '=?euc_jisx0213?b?pdOlw6XItdqk0zil06XDpcikzjKl0KWkpci+8MrzuPK0uc3RyeS55rK9s8jEpbTBu/q9uLnn?='
        for i in response.json()['results']:
            if i['type'] == 'email-subject':
                RFC_encoding_error = "The subject was not decoded from RFC2047 format."
                self.assertNotEqual(RFC_format, i['values'], RFC_encoding_error)
                self.assertEqual(japanese_charset, i['values'], "Subject not properly decoded")

    @unittest.skip("Need Rewrite")
    def test_email_malformed_header_emoji_encoding(self):
        query = {"module":"email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        # filenames = os.listdir("tests/test_files/encodings")
        # for encoding in ['utf-8', 'utf-16', 'utf-32']:
        message = get_base_email()
        text = """I am a test e-mail
        the password is NOT "this string".
        That is all.
        """
        message.attach(MIMEText(text, 'plain'))
        emoji_string = "Emoji Test 👍 checking this"
        emoji_bytes = emoji_string.encode()
        message.replace_header('Subject', "{{EMOJI}}")
        pat = re.compile(b'{{EMOJI}}')
        message_bytes = pat.sub(emoji_bytes, message.as_bytes())
        message64 = base64.b64encode(message_bytes).decode()
        query['data'] = message64
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        # Parse Response
        RFC_format = "=?unknown-8bit?q?Emoji_Test_=F0=9F=91=8D_checking_this?="
        for i in response.json()['results']:
            if i['type'] == 'email-subject':
                RFC_encoding_error = "The subject was not decoded from RFC2047 format."
                self.assertNotEqual(RFC_format, i['values'], RFC_encoding_error)
                self.assertEqual(emoji_string, i['values'], "Subject not properly decoded")

    @unittest.skip("Need Rewrite")
    def test_email_attachment_emoji_filename(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": None}
        message = get_base_email()
        text = """I am a test e-mail"""
        message.attach(MIMEText(text, 'plain'))
        with open("tests/EICAR.com", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'com')
            eicar_mime.add_header('Content-Disposition',
                                      'attachment',
                                      filename="Emoji Test 👍 checking this")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()['results']]
        self.assertIn("Emoji Test 👍 checking this", values)
        for i in response.json()['results']:
            if i["type"] == 'email-attachment':
                self.assertEqual(i["values"], "Emoji Test 👍 checking this")
            if i['type'] == 'malware-sample':
                attch_data = base64.b64decode(i["data"])
                self.assertEqual(attch_data, b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')


    @unittest.skip("Need Rewrite")
    def test_email_attachment_password_in_subject(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": "true",
                           "guess_zip_attachment_passwords": 'true',
                           "extract_urls": None}
        message = get_base_email()
        message.replace_header("Subject", 'I contain the -> "a long password" <- that is the password')
        text = """I am a test e-mail
        the password is NOT "this string".

        That is all.
        """
        message.attach(MIMEText(text, 'plain'))
        with open("tests/longer_password.zip", "rb") as fp:
            eicar_mime = MIMEApplication(fp.read(), 'zip')
            eicar_mime.add_header('Content-Disposition', 'attachment', filename="EICAR.com.zip")
            message.attach(eicar_mime)
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn('EICAR.com', values)
        self.assertIn('I contain the -> "a long password" <- that is the password', values)
        for i in response.json()['results']:
            # Check that it could be extracted.
            if i["values"] == 'EICAR.com':
                attch_data = base64.b64decode(i["data"]).decode()
                self.assertEqual(attch_data,
                                 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-')

    @unittest.skip("Need Rewrite")
    def test_email_extract_html_body_urls(self):
        query = {"module": "email_import"}
        query["config"] = {"unzip_attachments": None,
                           "guess_zip_attachment_passwords": None,
                           "extract_urls": "true"}
        message = get_base_email()
        text = """I am a test e-mail

        That is all.
        """
        html = """\
<html>
  <head></head>
  <body>
    <p>Hi!<br>
<p>MISP modules are autonomous modules that can be used for expansion and other services in <a href="https://github.com/MISP/MISP">MISP</a>.</p>
<p>The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration.</p>
<p>MISP modules support is included in MISP starting from version 2.4.28.</p>
<p>For more information: <a href="https://www.circl.lu/assets/files/misp-training/3.1-MISP-modules.pdf">Extending MISP with Python modules</a> slides from MISP training.</p>
    </p>
  </body>
</html>
"""
        message.attach(MIMEText(text, 'plain'))
        message.attach(MIMEText(html, 'html'))
        query['data'] = decode_email(message)
        data = json.dumps(query)
        response = requests.post(self.url + "query", data=data)
        # print(response.json())
        values = [x["values"] for x in response.json()["results"]]
        self.assertIn("https://github.com/MISP/MISP", values)
        self.assertIn("https://www.circl.lu/assets/files/misp-training/3.1-MISP-modules.pdf", values)

    # def test_domaintools(self):
    #    query = {'config': {'username': 'test_user', 'api_key': 'test_key'}, 'module': 'domaintools', 'domain': 'domaintools.com'}
    #    try:
    #        response = requests.post(self.url + "query", data=json.dumps(query)).json()
    #    except:
    #        pass
    #    response = requests.post(self.url + "query", data=json.dumps(query)).json()
    #    print(response)


def decode_email(message):
    message64 = base64.b64encode(message.as_bytes()).decode()
    return message64


def get_base_email():
    headers = {"Received": "via dmail-2008.19 for +INBOX; Tue, 3 Feb 2009 19:29:12 -0600 (CST)",
               "Received": "from abc.luxsci.com ([10.10.10.10]) by xyz.luxsci.com (8.13.7/8.13.7) with ESMTP id n141TCa7022588 for <test@domain.com>; Tue, 3 Feb 2009 19:29:12 -0600",
               "Received": "from [192.168.0.3] (verizon.net [44.44.44.44]) (user=test@sender.com mech=PLAIN bits=2) by abc.luxsci.com (8.13.7/8.13.7) with ESMTP id n141SAfo021855 (version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-SHA bits=256 verify=NOT) for <test@domain.com>; Tue, 3 Feb 2009 19:28:10 -0600",
               "X-Received": "by 192.168.0.45 with SMTP id q4mr156123401yw1g.911.1912342394963; Tue, 3 Feb 2009 19:32:15 -0600 (PST)",
               "Message-ID": "<4988EF2D.40804@example.com>",
               "Date": "Tue, 03 Feb 2009 20:28:13 -0500",
               "From": '"Innocent Person" <IgnoreMeImInnocent@sender.com>',
               "User-Agent": 'Thunderbird 2.0.0.19 (Windows/20081209)',
               "Sender": '"Malicious MailAgent" <mailagent@example.com>',
               "References": "<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>",
               "In-Reply-To": "<CI7DgL-A6dm92s7gf4-88g@E_0x238G4K2H08H9SDwsw8b6LwuA@mail.example.com>",
               "Accept-Language": 'en-US',
               "X-Mailer": 'mlx 5.1.7',
               "Return-Path": "evil_spoofer@example.com",
               "Thread-Topic": 'This is a thread.',
               "Thread-Index": 'AQHSR8Us3H3SoaY1oUy9AAwZfMF922bnA9GAgAAi9s4AAGvxAA==',
               "Content-Language": 'en-US',
               "To": '"Testy Testerson" <test@domain.com>',
               "Cc": '"Second Person" <second@domain.com>, "Other Friend" <other@friend.net>, "Last One" <last_one@finally.com>',
               "Subject": 'Example Message',
               "MIME-Version": '1.0'}
    msg = MIMEMultipart()
    for key, val in headers.items():
        msg.add_header(key, val)
    return msg


if __name__ == '__main__':
    unittest.main()
