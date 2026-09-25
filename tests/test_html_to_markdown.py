#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import Mock, patch

from misp_modules.modules.expansion.html_to_markdown import fetchHTML, is_safe_url


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

    def test_allows_public_ipv4_literal(self):
        self.assertTrue(is_safe_url("http://93.184.216.34/"))

    def test_allows_hostnames_resolving_to_public_ipv4_addresses(self):
        with patch(
            "misp_modules.modules.expansion.html_to_markdown.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 0))],
        ):
            self.assertTrue(is_safe_url("http://example.test/"))

    def test_blocks_hostnames_resolving_to_ipv4_mapped_blocked_addresses(self):
        with patch(
            "misp_modules.modules.expansion.html_to_markdown.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("::ffff:127.0.0.1", 0, 0, 0))],
        ):
            self.assertFalse(is_safe_url("http://example.test/"))

    def test_rejects_url_without_hostname(self):
        self.assertFalse(is_safe_url("http:///missing-host"))

    def test_rejects_backslash_authority_parser_differential(self):
        self.assertFalse(is_safe_url(r"http://127.0.0.1:8877\@1.1.1.1/"))

    @patch("misp_modules.modules.expansion.html_to_markdown.requests.get")
    def test_parser_differential_is_blocked_before_request(self, get):
        with self.assertRaisesRegex(ValueError, "Blocked URL"):
            fetchHTML(r"http://127.0.0.1:8877\@1.1.1.1/")
        get.assert_not_called()

    @patch("misp_modules.modules.expansion.html_to_markdown.requests.get")
    def test_blocks_redirect_to_loopback(self, get):
        response = Mock()
        response.is_redirect = True
        response.headers = {"location": "http://127.0.0.1/internal"}
        get.return_value = response

        with self.assertRaisesRegex(ValueError, "Blocked redirect URL"):
            fetchHTML("http://93.184.216.34/")

        get.assert_called_once_with(
            "http://93.184.216.34/", timeout=10, allow_redirects=False
        )
        response.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
