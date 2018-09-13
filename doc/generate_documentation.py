# -*- coding: utf-8 -*-
import os
import json

root_path = os.path.dirname(os.path.realpath(__file__))
module_types = ['expansion', 'export_mod', 'import_mod']
titles = ['Expansion Modules', 'Export Modules', 'Import Modules']
markdown= ["# MISP modules documentation\n"]
for _path, title in zip(module_types, titles):
    markdown.append('\n## {}\n'.format(title))
    current_path = os.path.join(root_path, _path)
    files = sorted(os.listdir(current_path))
    for _file in files:
        markdown.append('\n#### {}\n'.format(_file.split('.json')[0]))
        filename = os.path.join(current_path, _file)
        with open(filename, 'rt', encoding='utf-8') as f:
            definition = json.loads(f.read())
        if 'logo' in definition:
            markdown.append('\n<img src={} height=100>\n'.format(definition.pop('logo')))
        if 'description' in definition:
            markdown.append('\n{}\n'.format(definition.pop('description')))
        for field, value in definition.items():
            if value:
                value = ', '.join(value) if isinstance(value, list) else '{}'.format(value.replace('\n', '\n>'))
                markdown.append('- **{}**:\n>{}\n'.format(field, value))
        markdown.append('\n-----\n')
with open('documentation.md', 'w') as w:
    w.write(''.join(markdown))
