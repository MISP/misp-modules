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


def admin_user_active():
    return Config.ADMIN_USER

def admin_password():
    return Config.ADMIN_PASSWORD


