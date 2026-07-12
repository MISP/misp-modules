#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from misp_modules.modules.expansion.html_to_markdown import is_safe_url


class TestHtmlToMarkdownUrlSafety(unittest.TestCase):

    def test_blocks_ipv4_mapped_ipv6_literals_for_blocked_ipv4_ranges(self):
        blocked_urls = (
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:172.16.0.1]/",
            "http://[::ffff:192.168.0.1]/",
            "http://[::ffff:169.254.169.254]/",
        )

        for url in blocked_urls:
            with self.subTest(url=url):
                self.assertFalse(is_safe_url(url))

    def test_allows_public_ipv4_mapped_ipv6_literal(self):
        self.assertTrue(is_safe_url("http://[::ffff:93.184.216.34]/"))

    def test_blocks_hostnames_resolving_to_ipv4_mapped_blocked_addresses(self):
        with patch(
            "misp_modules.modules.expansion.html_to_markdown.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("::ffff:127.0.0.1", 0, 0, 0))],
        ):
            self.assertFalse(is_safe_url("http://example.test/"))

    def test_rejects_url_without_hostname(self):
        self.assertFalse(is_safe_url("http:///missing-host"))


if __name__ == "__main__":
    unittest.main()
