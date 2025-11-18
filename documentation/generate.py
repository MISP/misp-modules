#!/usr/bin/env python
import collections
import copy
import importlib
import importlib.resources
import logging
import os
import pathlib
import sys

logging.captureWarnings(True)


import misp_modules

GH_LINK = "https://github.com/MISP/misp-modules/tree/main/misp_modules/modules"
GH_DOC_LINK = "https://misp.github.io/misp-modules"

MODULE_TYPE_TITLE = {
    misp_modules.ModuleType.EXPANSION.value: "Expansion Modules",
    misp_modules.ModuleType.EXPORT_MOD.value: "Export Modules",
    misp_modules.ModuleType.IMPORT_MOD.value: "Import Modules",
    misp_modules.ModuleType.ACTION_MOD.value: "Action Modules",
}
MODULE_INFO_TO_IGNORE = ["module-type", "author", "version"]

# ./
BASE = pathlib.Path(__file__).resolve().parent.parent
# ./documentation/
DOC_ROOT = pathlib.Path(__file__).resolve().parent
# ./misp_modules/
SRC_ROOT = pathlib.Path(misp_modules.__file__).resolve().parent

ALL_MODULE_INFO = collections.defaultdict(dict)


def _get_all_module_info() -> dict:
    if not ALL_MODULE_INFO:
        # Load libraries as root modules
        misp_modules.promote_lib_to_root()
        for module_type, module in misp_modules.iterate_modules(SRC_ROOT.joinpath(misp_modules.MODULES_DIR)):
            module_name = os.path.splitext(module.name)[0]
            module_package_name = (
                f"{misp_modules.__package__}.{misp_modules.MODULES_DIR}.{module_type.name}.{module_name}"
            )
            try:
                module = importlib.import_module(module_package_name)
                module_info = copy.deepcopy(module.version())
            except ImportError:
                continue  # skip if we have issues loading the module
            ALL_MODULE_INFO[module_type.name][module_name] = dict(sorted(module_info.items()))

        # sort for good measure
        for module_type in list(ALL_MODULE_INFO.keys()):
            ALL_MODULE_INFO[module_type] = dict(sorted(ALL_MODULE_INFO[module_type].items(), key=lambda item: item[0]))
    return ALL_MODULE_INFO


def _generate_doc(module_type: str, logo_path: str = "logos") -> list[str]:
    markdown = []
    gh_path = f"{GH_LINK}/{module_type}"
    for module_name, module_info in _get_all_module_info()[module_type].items():
        gh_ref = f"{gh_path}/{module_name}.py"
        module_info = copy.deepcopy(module_info)
        for i in MODULE_INFO_TO_IGNORE:
            module_info.pop(i)
        try:
            module_name_pretty = module_info.pop("name")
        except KeyError:
            exit(f"ERROR: Issue with module {module_name} - no field 'name' provided")
        if module_name_pretty == "":
            module_name_pretty = module_name
        markdown.append(f"\n#### [{module_name_pretty}]({gh_ref})\n")
        if 'logo' in module_info:
            if module_info["logo"] != "":
                logo = os.path.join(logo_path, module_info.pop("logo"))
                markdown.append(f"\n<img src={logo} height=60>\n")
        if "description" in module_info:
            markdown.append(f"\n{module_info.pop('description')}\n")
        markdown.append(f"[[source code]({gh_ref})]\n")
        if "features" in module_info:
            markdown.append(_get_single_value("features", str(module_info.pop("features")).replace("\n", "\n>")))
        for field, value in sorted(module_info.items()):
            if not value:
                continue
            if isinstance(value, list):
                markdown.append(_handle_list(field, value))
                continue
            markdown.append(_get_single_value(field, str(value).replace("\n", "\n>")))
        markdown.append("\n-----\n")
    return markdown


def _generate_index_doc(module_type: str) -> list[str]:
    markdown = []
    for module_name, module_info in _get_all_module_info()[module_type].items():
        module_name_pretty = module_info.get("name", module_name)
        anchor_ref = f"{GH_DOC_LINK}/{module_type}/#{module_name_pretty.replace(' ', '-').lower()}"
        description_without_newlines = module_info.get("description").replace("\n", " ")
        markdown.append(f"* [{module_name_pretty}]({anchor_ref}) - {description_without_newlines}\n")
    return markdown


def _get_single_value(field: str, value: str) -> str:
    return f"\n- **{field}**:\n>{value}\n"


def _handle_list(field: str, values: list[str]) -> str:
    if len(values) == 1:
        return _get_single_value(field, values[0])
    values = "\n> - ".join(values)
    return f"\n- **{field}**:\n> - {values}\n"


def write_doc_for_readme():
    markdown = ["# MISP modules documentation\n"]
    for path, title in MODULE_TYPE_TITLE.items():
        markdown.append(f"\n## {title}\n")
        markdown.extend(_generate_doc(path))
    with open(DOC_ROOT.joinpath("README.md"), "w") as w:
        w.write("".join(markdown))


def write_docs_for_mkdocs():
    for path, title in MODULE_TYPE_TITLE.items():
        markdown = _generate_doc(path, logo_path="../logos")
        with open(os.path.join(DOC_ROOT.joinpath("mkdocs", f"{path}.md")), "w") as w:
            w.write("".join(markdown))


def update_docs_for_mkdocs_index():
    with open(DOC_ROOT.joinpath("mkdocs", "index.md"), "r") as r:
        old_doc = r.readlines()
    new_doc = []
    skip = False
    for line in old_doc:
        if skip and not line.startswith("## "):  # find next title
            continue  # skip lines, as we're in the block that we're auto-generating
        skip = False
        new_doc.append(line)
        if line.startswith("## Existing MISP modules"):
            skip = True
            for path, title in MODULE_TYPE_TITLE.items():
                new_doc.append(f"\n### {title}\n")
                new_doc.extend(_generate_index_doc(path))
            new_doc.append("\n\n")
    with open(DOC_ROOT.joinpath("mkdocs", "index.md"), "w") as w:
        w.write("".join(new_doc))


def update_readme():
    with open(BASE.joinpath("README.md"), "r") as r:
        old_readme = r.readlines()
    new_doc = []
    skip = False
    for line in old_readme:
        if skip and not line.startswith("# List of MISP modules"):  # find next title
            continue  # skip lines, as we're in the block that we're auto-generating
        new_doc.append(line)
        if line.startswith("# List of MISP modules"):
            skip = True
            for path, title in MODULE_TYPE_TITLE.items():
                new_doc.append(f"\n## {title}\n")
                new_doc.extend(_generate_index_doc(path))
            new_doc.append("\n\n")
    with open(BASE.joinpath("README.md"), "w") as w:
        w.write("".join(new_doc))


def main():
    """Generate documentation."""
    write_doc_for_readme()
    write_docs_for_mkdocs()
    update_docs_for_mkdocs_index()
    update_readme()
    return 0


if __name__ == "__main__":
    sys.exit(main())
