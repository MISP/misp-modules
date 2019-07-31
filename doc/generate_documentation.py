# -*- coding: utf-8 -*-
import os
import json

module_types = ['expansion', 'export_mod', 'import_mod']
titles = ['Expansion Modules', 'Export Modules', 'Import Modules']
markdown = ["# MISP modules documentation\n"]
githublink = 'https://github.com/MISP/misp-modules/tree/master/misp_modules/modules'


def generate_doc(root_path):
    for _path, title in zip(module_types, titles):
        markdown.append('\n## {}\n'.format(title))
        current_path = os.path.join(root_path, _path)
        files = sorted(os.listdir(current_path))
        githubpath = '{}/{}'.format(githublink, _path)
        for _file in files:
            modulename = _file.split('.json')[0]
            githubref = '{}/{}.py'.format(githubpath, modulename)
            markdown.append('\n#### [{}]({})\n'.format(modulename, githubref))
            filename = os.path.join(current_path, _file)
            with open(filename, 'rt') as f:
                definition = json.loads(f.read())
            if 'logo' in definition:
                markdown.append('\n<img src={} height=60>\n'.format(definition.pop('logo')))
            if 'description' in definition:
                markdown.append('\n{}\n'.format(definition.pop('description')))
            for field, value in sorted(definition.items()):
                if value:
                    value = ', '.join(value) if isinstance(value, list) else '{}'.format(value.replace('\n', '\n>'))
                    markdown.append('- **{}**:\n>{}\n'.format(field, value))
            markdown.append('\n-----\n')
    with open('README.md', 'w') as w:
        w.write(''.join(markdown))

def generate_docs_for_mkdocs(root_path):
    for _path, title in zip(module_types, titles):
        markdown = []
        #markdown.append('## {}\n'.format(title))
        current_path = os.path.join(root_path, _path)
        files = sorted(os.listdir(current_path))
        githubpath = '{}/{}'.format(githublink, _path)
        for _file in files:
            modulename = _file.split('.json')[0]
            githubref = '{}/{}.py'.format(githubpath, modulename)
            markdown.append('\n#### [{}]({})\n'.format(modulename, githubref))
            filename = os.path.join(current_path, _file)
            with open(filename, 'rt') as f:
                definition = json.loads(f.read())
            if 'logo' in definition:
                markdown.append('\n<img src={} height=60>\n'.format(definition.pop('logo')))
            if 'description' in definition:
                markdown.append('\n{}\n'.format(definition.pop('description')))
            for field, value in sorted(definition.items()):
                if value:
                    value = ', '.join(value) if isinstance(value, list) else '{}'.format(value.replace('\n', '\n>'))
                    markdown.append('- **{}**:\n>{}\n'.format(field, value))
            markdown.append('\n-----\n')
        with open(root_path+"/../"+"/docs/"+_path+".md", 'w') as w:
            w.write(''.join(markdown))

if __name__ == '__main__':
    root_path = os.path.dirname(os.path.realpath(__file__))
    generate_doc(root_path)
    generate_docs_for_mkdocs(root_path)
