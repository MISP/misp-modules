#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import io
import json
import unittest

import pandas

from misp_modules.modules.expansion.xlsx_enrich import handler


def _xlsx_attachment():
    buffer = io.BytesIO()
    pandas.DataFrame({"ioc": ["1.2.3.4"]}).to_excel(buffer, index=False)
    return base64.b64encode(buffer.getvalue()).decode()


class TestXlsxEnrich(unittest.TestCase):

    def test_handler_extracts_text_from_xlsx(self):
        query = json.dumps({"attachment": "test.xlsx", "data": _xlsx_attachment()})

        result = handler(query)

        self.assertNotIn("error", result)
        self.assertIn("1.2.3.4", result["results"][0]["values"])

    def test_handler_sets_unlimited_column_width(self):
        query = json.dumps({"attachment": "test.xlsx", "data": _xlsx_attachment()})

        handler(query)

        self.assertIsNone(pandas.get_option("display.max_colwidth"))
