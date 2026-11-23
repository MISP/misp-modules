#!/usr/bin/env python
import argparse
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
MODULE_LIST_HEADING = "## Existing MISP modules"

MODULE_TYPE_TITLE = {
    misp_modules.ModuleType.EXPANSION.value: "Expansion Modules",
    misp_modules.ModuleType.EXPORT_MOD.value: "Export Modules",
    misp_modules.ModuleType.IMPORT_MOD.value: "Import Modules",
    misp_modules.ModuleType.ACTION_MOD.value: "Action Modules",
    misp_modules.ModuleType.GATHERING.value: "Gathering Modules",
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


def _generate_index_doc(module_type: str, *, for_readme: bool = False) -> list[str]:
    markdown = []
    for module_name, module_info in _get_all_module_info()[module_type].items():
        module_name_pretty = module_info.get("name") or module_name
        description = module_info["description"].replace("\n", " ").strip()
        if for_readme:
            doc_dir = pathlib.Path("documentation", module_type)
            target = doc_dir / f"{module_name}.md"
            if not (BASE / target).is_file():
                target = pathlib.Path("misp_modules", misp_modules.MODULES_DIR, module_type, f"{module_name}.py")
            link = target.as_posix()
            json_doc = doc_dir / f"{module_name}.json"
            if (BASE / json_doc).is_file():
                description += f" [JSON documentation]({json_doc.as_posix()})."
        else:
            link = f"{GH_DOC_LINK}/{module_type}/#{module_name_pretty.replace(' ', '-').lower()}"
        markdown.append(f"* [{module_name_pretty}]({link}) - {description}\n")
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
        if line.startswith(MODULE_LIST_HEADING):
            skip = True
            for path, title in MODULE_TYPE_TITLE.items():
                new_doc.append(f"\n### {title}\n")
                new_doc.extend(_generate_index_doc(path))
            new_doc.append("\n\n")
    with open(DOC_ROOT.joinpath("mkdocs", "index.md"), "w") as w:
        w.write("".join(new_doc))


def update_readme() -> bool:
    module_info = _get_all_module_info()
    missing = sorted(
        f"{module_type.name}/{module.name}"
        for module_type, module in misp_modules.iterate_modules(SRC_ROOT / misp_modules.MODULES_DIR)
        if module.stem not in module_info.get(module_type.name, {})
    )
    if missing:
        logging.warning(
            "Skipped README regeneration because these modules could not be imported: %s", ", ".join(missing)
        )
        return False

    readme = BASE / "README.md"
    lines = readme.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next((index + 1 for index, line in enumerate(lines) if line.rstrip() == MODULE_LIST_HEADING), None)
    if start is None:
        raise SystemExit(f"README.md is missing the {MODULE_LIST_HEADING!r} heading.")
    end = next((index for index in range(start, len(lines)) if lines[index].startswith(("# ", "## "))), len(lines))

    catalog = ["\n<!-- Regenerate with: poetry run python documentation/generate.py --readme-only -->\n"]
    for path, title in MODULE_TYPE_TITLE.items():
        catalog.append(f"\n### {title}\n")
        catalog.extend(_generate_index_doc(path, for_readme=True))
    if end < len(lines):
        catalog.append("\n")
    readme.write_text("".join([*lines[:start], *catalog, *lines[end:]]), encoding="utf-8")
    return True


def main():
    """Generate documentation."""
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--readme-only", action="store_true", help="Update the module list in the root README only.")
    if parser.parse_args().readme_only:
        return 0 if update_readme() else 1

    write_doc_for_readme()
    write_docs_for_mkdocs()
    update_docs_for_mkdocs_index()
    update_readme()
    return 0


if __name__ == "__main__":
    sys.exit(main())
