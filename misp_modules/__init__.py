#
# Core MISP expansion modules loader and web service
#
# Copyright (C) 2016 Alexandre Dulaunoy
# Copyright (C) 2016 CIRCL - Computer Incident Response Center Luxembourg
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import enum
import importlib
import importlib.abc
import importlib.metadata
import importlib.resources
import importlib.util
import pathlib
import sys
import types
import typing

import psutil

# Constants
LIBRARY_DIR = "lib"
MODULES_DIR = "modules"
HELPERS_DIR = "helpers"


class ModuleType(enum.Enum):
    """All the modules types."""

    EXPANSION = "expansion"
    EXPORT_MOD = "export_mod"
    IMPORT_MOD = "import_mod"
    ACTION_MOD = "action_mod"


def get_version() -> str:
    """Return the version."""
    try:
        return importlib.metadata.version("misp-modules")
    except importlib.metadata.PackageNotFoundError:
        raise ValueError


def is_valid_module(module: importlib.abc.Traversable) -> bool:
    """Whether the reference is a valid module file."""
    if not module.is_file():
        return False
    if module.name == "__init__.py":
        return False
    if not module.name.endswith(".py"):
        return False
    return True


def is_valid_module_type(module_type: importlib.abc.Traversable) -> bool:
    """Whether the reference is a valid module type."""
    if not module_type.is_dir():
        return False
    try:
        ModuleType(module_type.name)
    except ValueError:
        return False
    return True


def iterate_modules(
    modules_dir: typing.Union[importlib.abc.Traversable, pathlib.Path],
) -> typing.Generator[tuple[importlib.abc.Traversable, importlib.abc.Traversable], None, None]:
    """Iterate modules and return both module types and module references."""
    for module_type in modules_dir.iterdir():
        if is_valid_module_type(module_type):
            for module in module_type.iterdir():
                if is_valid_module(module):
                    yield module_type, module


def import_from_path(module_name: str, file_path: str) -> types.ModuleType:
    """Import module from any point in the file system."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def get_misp_modules_pid() -> typing.Union[int, None]:
    """Get the pid of any process that have `misp-modules` in the command line."""
    try:
        for pid in psutil.pids():
            if any("misp-modules" in x for x in psutil.Process(pid).cmdline()):
                return pid
        return None
    except psutil.AccessDenied:
        return None


def promote_lib_to_root() -> None:
    """Nested libraries are called as full fledge libraries."""
    sys.path.append(str(importlib.resources.files(__package__).joinpath(LIBRARY_DIR)))
