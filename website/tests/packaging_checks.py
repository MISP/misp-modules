"""Test the website wheel outside the checkout, without a module dependency."""

import subprocess
import sys
import textwrap
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory


class WebsitePackagingChecks(unittest.TestCase):
    def test_csv_download_from_wheel_without_misp_modules(self):
        website = Path(__file__).resolve().parents[1]
        with TemporaryDirectory(prefix="misp-website-wheel-") as directory:
            build = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from poetry.core.masonry.api import build_wheel; "
                    "import sys; build_wheel(sys.argv[1])",
                    directory,
                ],
                cwd=website,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            wheel = next(Path(directory).glob("*.whl"))
            installed = Path(directory) / "installed"
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(installed)
            check = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    textwrap.dedent("""\
                    import csv
                    import importlib.abc
                    import io
                    import json
                    import os
                    import sys
                    from types import SimpleNamespace
                    from unittest.mock import patch

                    class NoModulePackage(importlib.abc.MetaPathFinder):
                        def find_spec(self, fullname, path=None, target=None):
                            if fullname == 'misp_modules' or fullname.startswith('misp_modules.'):
                                raise ModuleNotFoundError(fullname)

                    sys.meta_path.insert(0, NoModulePackage())
                    sys.path.insert(0, sys.argv[1])
                    os.environ['SECRET_KEY'] = 'packaging-regression-test'
                    os.environ['DATABASE_URI'] = 'sqlite://'
                    import app
                    assert sys.argv[1] in app.__file__, app.__file__
                    client = app.create_app().test_client()
                    for result in [
                        {'results': [{'types': ['text'], 'values': ['café, "quoted"', '=1+1']}]},
                        {'results': {'Object': [{'name': 'report', 'Attribute': [
                            {'type': 'text', 'value': 'café, "quoted"'},
                            {'type': 'text', 'value': '=1+1'},
                        ]}]}},
                    ]:
                        saved = SimpleNamespace(result=json.dumps({'query': {'module': result}}))
                        with patch('app.home.HomeModel.get_session', return_value=saved):
                            response = client.get('/download/session?query=query&module=module&format=csv')
                        assert response.status_code == 200, response.data
                        rows = list(csv.DictReader(io.StringIO(response.data.decode('utf-8'))))
                        assert [row['value'] for row in rows] == ['café, "quoted"', "'=1+1"]
                    """),
                    str(installed),
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
