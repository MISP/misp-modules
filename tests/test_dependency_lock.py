"""Check lock selections before Poetry can install overlapping distributions.

Run with ``python tests/test_dependency_lock.py`` after installing Poetry and
before installing the project. Only stdlib and Poetry's packaging dependency
are needed; pytest and project dependencies need not be installed yet.
"""

import itertools
import unittest
from collections import defaultdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, outside the CI interpreter matrix.
    import tomli as tomllib

from packaging.markers import Marker, default_environment
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSIONS = ("3.10.0", "3.11.0", "3.11.5", "3.12.0", "3.13.0", "3.14.0", "3.15.0")
PLATFORMS = (("linux", "Linux", "posix"), ("darwin", "Darwin", "posix"), ("win32", "Windows", "nt"))
GROUPS = (("main",), ("main", "test"), ("main", "docs"))
EXTRAS = ("", "minimal", "all")


def selections(packages, environment, groups):
    versions = set()
    for package in packages:
        active_groups = set(package["groups"]) & set(groups)
        if not active_groups or not package["python_constraint"].contains(environment["python_full_version"]):
            continue
        markers = package["parsed_markers"]
        if isinstance(markers, dict):
            active = any(markers.get(group) is None or markers[group].evaluate(environment) for group in active_groups)
        else:
            active = markers is None or markers.evaluate(environment)
        if active:
            versions.add(package["version"])
    return versions


class TestDependencyLock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / "poetry.lock").open("rb") as stream:
            locked = tomllib.load(stream)
        cls.packages = defaultdict(list)
        for package in locked["package"]:
            constraint = package.get("python-versions", "*")
            package["python_constraint"] = SpecifierSet("" if constraint == "*" else constraint)
            markers = package.get("markers")
            package["parsed_markers"] = (
                {group: Marker(value) for group, value in markers.items()}
                if isinstance(markers, dict)
                else Marker(markers) if markers else None
            )
            cls.packages[canonicalize_name(package["name"])].append(package)

    def test_each_environment_selects_at_most_one_version(self):
        conflicts = []
        candidates = {name: packages for name, packages in self.packages.items() if len(packages) > 1}
        for python, platform, groups, extra in itertools.product(PYTHON_VERSIONS, PLATFORMS, GROUPS, EXTRAS):
            environment = default_environment()
            environment.update(
                python_version=".".join(python.split(".")[:2]),
                python_full_version=python,
                implementation_version=python,
                implementation_name="cpython",
                platform_python_implementation="CPython",
                sys_platform=platform[0],
                platform_system=platform[1],
                os_name=platform[2],
                extra=extra,
            )
            for name, packages in candidates.items():
                versions = selections(packages, environment, groups)
                if len(versions) > 1:
                    conflicts.append(
                        f"Python {python}, {platform[0]}, groups={groups}, extra={extra!r}: {name} {sorted(versions)}"
                    )
        if conflicts:
            self.fail(f"Lock selects conflicting versions in {len(conflicts)} cases:\n" + "\n".join(conflicts[:12]))

    def test_scientific_stack_keeps_a_version_for_each_supported_python(self):
        for python, extra, name in itertools.product(
            PYTHON_VERSIONS, ("minimal", "all"), ("numpy", "contourpy", "deprecated", "soupsieve")
        ):
            environment = default_environment()
            environment.update(
                python_version=".".join(python.split(".")[:2]),
                python_full_version=python,
                implementation_version=python,
                extra=extra,
            )
            with self.subTest(python=python, extra=extra, package=name):
                self.assertEqual(len(selections(self.packages[name], environment, ("main",))), 1)


if __name__ == "__main__":
    unittest.main()
