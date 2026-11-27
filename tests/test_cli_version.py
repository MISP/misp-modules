import subprocess
import sys
import unittest
from unittest import mock

import misp_modules
from misp_modules import __main__ as server


class TestCliVersion(unittest.TestCase):

    def test_version_flags_print_the_installed_version_and_exit(self):
        for flag in ("-v", "--version"):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, "-m", "misp_modules", flag], capture_output=True, text=True, timeout=120, check=False
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                try:
                    expected = misp_modules.get_version()
                except ValueError:
                    expected = "unknown"
                self.assertEqual(result.stdout.strip(), f"misp-modules {expected}")

    def test_unknown_version_when_not_installed(self):
        with mock.patch.object(misp_modules, "get_version", side_effect=ValueError):
            self.assertEqual(server._installed_version(), "unknown")
