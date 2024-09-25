# -*- coding: utf-8 -*-
import os
from pathlib import Path
import importlib
import copy

module_types = ['expansion', 'export_mod', 'import_mod', 'action_mod']
titles = ['Expansion Modules', 'Export Modules', 'Import Modules', 'Action Modules']
githublink = 'https://github.com/MISP/misp-modules/tree/main/misp_modules/modules'
githubiolink = 'https://misp.github.io/misp-modules'

moduleinfo_to_ignore = ['module-type', 'author', 'version']

_all_moduleinfo = {}


def get_all_moduleinfo():
    '''
    Get all module information from the modules.
    Behaves like a singleton, so it will only load the modules once.
    '''
    if not _all_moduleinfo:
        for module_type in module_types:
            _all_moduleinfo[module_type] = {}
            module_type_module = importlib.import_module(f"misp_modules.modules.{module_type}")
            module_type_module.__all__.sort()
            for module_name in module_type_module.__all__:
                module_package_name = f"misp_modules.modules.{module_type}.{module_name}"
                try:
                    module = importlib.import_module(module_package_name)
                    moduleinfo = copy.deepcopy(module.version())
                except Exception:
                    continue  # skip if we have issues loading the module

                moduleinfo = dict(sorted(moduleinfo.items()))
                _all_moduleinfo[module_type][module_name] = moduleinfo

    return _all_moduleinfo


def generate_doc(module_type, root_path, logo_path='logos'):
    markdown = []
    # current_path = os.path.join(root_path, 'website', module_type)
    # files = sorted(os.listdir(current_path))
    githubpath = f'{githublink}/{module_type}'

    for module_name, moduleinfo in get_all_moduleinfo()[module_type].items():
        githubref = f'{githubpath}/{module_name}.py'

        moduleinfo = copy.deepcopy(moduleinfo)  # ensure to not modify the original data
        for i in moduleinfo_to_ignore:
            moduleinfo.pop(i)

        try:
            module_name_pretty = moduleinfo.pop('name')
        except KeyError:
            exit(f"ERROR: Issue with module {module_name} - no field 'name' provided")
        if module_name_pretty == '':
            module_name_pretty = module_name

        markdown.append(f'\n#### [{module_name_pretty}]({githubref})\n')
        if moduleinfo['logo'] != '':
            logo = os.path.join(logo_path, moduleinfo.pop('logo'))
            markdown.append(f"\n<img src={logo} height=60>\n")
        if 'description' in moduleinfo:
            markdown.append(f"\n{moduleinfo.pop('description')}\n")
        markdown.append(f"[[source code]({githubref})]\n")
        if 'features' in moduleinfo:
            markdown.append(get_single_value('features', str(moduleinfo.pop('features')).replace('\n', '\n>')))
        for field, value in sorted(moduleinfo.items()):
            if not value:
                continue
            if isinstance(value, list):
                markdown.append(handle_list(field, value))
                continue
            markdown.append(get_single_value(field, str(value).replace('\n', '\n>')))
        markdown.append('\n-----\n')
    return markdown


def generate_index_doc(module_type, root_path):
    markdown = []
    for module_name, moduleinfo in get_all_moduleinfo()[module_type].items():
        module_name_pretty = moduleinfo.get('name')
        if module_name_pretty == '':
            module_name_pretty = module_name

        anchor_ref = f"{githubiolink}/{module_type}/#{module_name_pretty.replace(' ', '-').lower()}"
        description_without_newlines = moduleinfo.get("description").replace('\n', ' ')
        markdown.append(f'* [{module_name_pretty}]({anchor_ref}) - {description_without_newlines}\n')
    return markdown


def get_single_value(field, value):
    return f"\n- **{field}**:\n>{value}\n"


def handle_list(field, values):
    if len(values) == 1:
        return get_single_value(field, values[0])
    values = '\n> - '.join(values)
    return f"\n- **{field}**:\n> - {values}\n"


def write_doc_for_readme(root_path):
    markdown = ["# MISP modules documentation\n"]
    for _path, title in zip(module_types, titles):
        markdown.append(f'\n## {title}\n')
        markdown.extend(generate_doc(_path, root_path))
    with open(root_path / 'README.md', 'w') as w:
        w.write(''.join(markdown))


def write_docs_for_mkdocs(root_path):
    for _path, title in zip(module_types, titles):
        markdown = generate_doc(_path, root_path, logo_path='../logos')
        with open(os.path.join(root_path, 'mkdocs', f'{_path}.md'), 'w') as w:
            w.write(''.join(markdown))


def update_docs_for_mkdocs_index(root_path):
    with open(root_path / 'mkdocs' / 'index.md', 'r') as r:
        old_doc = r.readlines()

    new_doc = []
    skip = False
    for line in old_doc:
        if skip and not line.startswith('## '):  # find next title
            continue   # skip lines, as we're in the block that we're auto-generating

        skip = False
        new_doc.append(line)

        if line.startswith('## Existing MISP modules'):
            skip = True
            # generate the updated content
            for _path, title in zip(module_types, titles):
                new_doc.append(f'\n### {title}\n')
                new_doc.extend(generate_index_doc(_path, root_path))
            new_doc.append('\n\n')

    with open(root_path / 'mkdocs' / 'index.md', 'w') as w:
        w.write(''.join(new_doc))
    pass


def update_readme(root_path):
    with open(root_path / 'README.md', 'r') as r:
        old_readme = r.readlines()

    new_doc = []
    skip = False
    for line in old_readme:
        if skip and not line.startswith('# List of MISP modules'):  # find next title
            continue   # skip lines, as we're in the block that we're auto-generating

        new_doc.append(line)

        if line.startswith('# List of MISP modules'):
            skip = True
            # generate the updated content
            for _path, title in zip(module_types, titles):
                new_doc.append(f'\n## {title}\n')
                new_doc.extend(generate_index_doc(_path, root_path))
            new_doc.append('\n\n')

    with open(root_path / 'README.md', 'w') as w:
        w.write(''.join(new_doc))
    pass


if __name__ == '__main__':
    root_path = Path(__file__).resolve().parent

    write_doc_for_readme(root_path)
    write_docs_for_mkdocs(root_path)
    update_docs_for_mkdocs_index(root_path)
    update_readme(root_path.parent)
