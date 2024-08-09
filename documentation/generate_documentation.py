# -*- coding: utf-8 -*-
import os
import json
from pathlib import Path

module_types = ['expansion', 'export_mod', 'import_mod']
titles = ['Expansion Modules', 'Export Modules', 'Import Modules']
githublink = 'https://github.com/MISP/misp-modules/tree/main/misp_modules/modules'


def generate_doc(module_type, root_path, logo_path='logos'):
    markdown = []
    current_path = os.path.join(root_path, 'website', module_type)
    files = sorted(os.listdir(current_path))
    githubpath = f'{githublink}/{module_type}'
    for filename in files:
        modulename = filename.split('.json')[0]
        githubref = f'{githubpath}/{modulename}.py'
        markdown.append(f'\n#### [{modulename}]({githubref})\n')
        filename = os.path.join(current_path, filename)
        print(f'Processing {filename}')
        with open(filename, 'rt') as f:
            definition = json.loads(f.read())
        if 'logo' in definition:
            logo = os.path.join(logo_path, definition.pop('logo'))
            markdown.append(f"\n<img src={logo} height=60>\n")
        if 'description' in definition:
            markdown.append(f"\n{definition.pop('description')}\n")
        for field, value in sorted(definition.items()):
            if not value:
                continue
            if isinstance(value, list):
                markdown.append(handle_list(field, value))
                continue
            markdown.append(get_single_value(field, value.replace('\n', '\n>')))
        markdown.append('\n-----\n')
    return markdown


def get_single_value(field, value):
    return f"- **{field}**:\n>{value}\n"


def handle_list(field, values):
    if len(values) == 1:
        return get_single_value(field, values[0])
    values = '\n> - '.join(values)
    return f"- **{field}**:\n> - {values}\n"


def write_doc(root_path):
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


if __name__ == '__main__':
    root_path = Path(__file__).resolve().parent
    write_doc(root_path)
    write_docs_for_mkdocs(root_path)
