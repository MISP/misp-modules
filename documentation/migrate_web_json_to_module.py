import json
import re
from pathlib import Path
import os

module_types = ['expansion', 'export_mod', 'import_mod']

moduleinfo_template = {
    'version': '1.0',
    'author': '',
    'module-type': [],
    'description': '',
    'logo': '',
    'requirements': [],
    'features': '',
    'references': [],
    'input': '',
    'output': ''
}

if __name__ == '__main__':
    exit("This code was temporary and should not be run again. It was used to migrate the JSON documentation to the module files.")
    root_path = Path(__file__).resolve().parent.parent
    modules_path = root_path / 'misp_modules' / 'modules'

    for module_type in module_types:
        files = sorted(os.listdir(modules_path / module_type))
        for python_filename in files:
            if not python_filename.endswith('.py') or '__init__' in python_filename:
                continue
            modulename = python_filename.split('.py')[0]
            json_filename = root_path / 'documentation' / 'website' / module_type / f'{modulename}.json'
            print(f"Processing type {module_type}:{modulename} in {python_filename} and {json_filename}")
            json_exists = json_filename.exists()
            if json_exists:
                print(" Found JSON file")
                with open(json_filename, 'rt') as f:
                    json_content = json.loads(f.read())
            else:
                json_content = {}
            # if json does not exist, then still edit the python file and add the stub structure
            with open(modules_path / module_type / python_filename, 'r+t') as python_f:
                # read from python file, find moduleinfo and load it as python variable
                python_content = python_f.read()
                re_pattern = r'moduleinfo\s=\s{[^}]*}'
                m = re.search(re_pattern, python_content, re.MULTILINE | re.DOTALL)
                if not m:
                    print(f" Moduleinfo not found in {python_filename}")
                    continue
                s = m.group(0)
                moduleinfo = {}
                exec(s)  # we now have a moduleinfo dict
                print(f" Moduleinfo found in {python_filename}: {moduleinfo}")
                # populate from template
                for k, v in moduleinfo_template.items():
                    if k not in moduleinfo or moduleinfo.get(k) == '' or moduleinfo.get(k) == []:
                        # print(f" Adding {k} = {v} to {python_filename}")
                        moduleinfo[k] = v
                # populate from json
                for k, v in json_content.items():
                    if k not in moduleinfo or moduleinfo.get(k) == '' or moduleinfo.get(k) == []:
                        # print(f" Adding {k} = {v} to {python_filename}")
                        moduleinfo[k] = v
                if json_content and json_content.get('description') != moduleinfo.get('description'):
                    print(" WARNING: Description in JSON and Python file do not match:")
                    print("")
                    print(f" JSON: {json_content.get('description')}")
                    print("")
                    print(f" Python: {moduleinfo.get('description')}")
                    print("")
                    user_input = input("Which version do you want to use? Enter '[j]son' for JSON version or '[p]ython' for Python version, or any other text for a new description: ")

                    if user_input in ['json', 'j', 'JSON']:
                        moduleinfo['description'] = json_content['description']
                    elif user_input in ['python', 'p', 'PYTHON']:
                        pass
                    else:
                        moduleinfo['description'] = user_input.strip()

                # write back to python file
                new_moduleinfo_text = ['moduleinfo = {']
                for k, v in moduleinfo.items():
                    v_updated = repr(v).replace('\\', '\\\\')
                    new_moduleinfo_text.append(f"    '{k}': {v_updated},")
                new_moduleinfo_text.append('}')

                python_content_new, cnt = re.subn(re_pattern, '\n'.join(new_moduleinfo_text), python_content, re.MULTILINE | re.DOTALL)
                if cnt == 0:
                    print(f" WARNING: Moduleinfo not replaced in {python_filename}")
                    continue
                python_f.seek(0)
                python_f.write(python_content_new)
                python_f.truncate()  # remove the rest of the file
                pass

    pass
