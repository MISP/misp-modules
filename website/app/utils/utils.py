import os
import uuid
import json
import requests
# import jsonschema
from config import Config
from pathlib import Path

MODULES = []

def query_get_module(headers={'Content-type': 'application/json'}):
    global MODULES
    if not MODULES:
        try:
            r = requests.get(f"http://{Config.MISP_MODULE}/modules", headers=headers)
        except ConnectionError:
            return {"message": "Instance of misp-modules is unreachable"}
        except Exception as e:
            return {"message": e}
        MODULES = r.json()
        return r.json()
    else:
        return MODULES

def query_post_query(data, headers={'Content-type': 'application/json'}):
    try:
        r = requests.post(f"http://{Config.MISP_MODULE}/query", data=json.dumps(data), headers=headers)
    except ConnectionError:
        return {"message": "Instance of misp-modules is unreachable"}
    except Exception as e:
        return {"message": e}
    return r.json()


def isUUID(uid):
    try:
        uuid.UUID(str(uid))
        return True
    except ValueError:
        return False
    
def get_object(obj_name):
    path = Path(os.getcwd())
    parent_path = path.parent.absolute()
    loc_path = os.path.join(parent_path, "misp_modules", "lib", "misp-objects", "objects")
    if os.path.isdir(loc_path):
        with open(os.path.join(loc_path, obj_name, "definition.json"), "r") as read_json:
            loc_json = json.load(read_json)
        return loc_json
    return False
    


# def form_to_dict(form):
#     loc_dict = dict()
#     for field in form._fields:
#         if field == "files_upload":
#             loc_dict[field] = dict()
#             loc_dict[field]["data"] = form._fields[field].data
#             loc_dict[field]["name"] = form._fields[field].name
#         elif not field == "submit" and not field == "csrf_token":
#             loc_dict[field] = form._fields[field].data
#     return loc_dict

# def create_specific_dir(specific_dir):
#     if not os.path.isdir(specific_dir):
#         os.mkdir(specific_dir)


# caseSchema = {
#     "type": "object",
#     "properties": {
#         "title": {"type": "string"},
#         "description": {"type": "string"},
#         "uuid": {"type": "string"},
#         "deadline:": {"type": "string"},
#         "recurring_date:": {"type": "string"},
#         "recurring_type:": {"type": "string"},
#         "tasks": {
#             "type": "array", 
#             "items": {"type": "object"},
#         },
#         "tags":{
#             "type": "array",
#             "items": {"type": "string"},
#         },
#         "clusters":{
#             "type": "array",
#             "items": {"type": "string"},
#         },
#     },
#     "required": ['title']
# }

# taskSchema = {
#     "type": "object",
#     "properties": {
#         "title": {"type": "string"},
#         "description": {"type": "string"},
#         "uuid": {"type": "string"},
#         "deadline:": {"type": "string"},
#         "url:": {"type": "string"},
#         "notes:": {"type": "string"},
#         "tags":{
#             "type": "array",
#             "items": {"type": "string"}
#         },
#         "clusters":{
#             "type": "array",
#             "items": {"type": "string"},
#         },
#     },
#     "required": ['title']
# }

# def validateCaseJson(json_data):
#     try:
#         jsonschema.validate(instance=json_data, schema=caseSchema)
#     except jsonschema.exceptions.ValidationError as err:
#         print(err)
#         return False
#     return True

# def validateTaskJson(json_data):
#     try:
#         jsonschema.validate(instance=json_data, schema=taskSchema)
#     except jsonschema.exceptions.ValidationError as err:
#         print(err)
#         return False
#     return True

