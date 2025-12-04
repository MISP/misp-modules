#!/usr/bin/env python3
import json
import os
import random
import uuid
from pathlib import Path

import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Cache environment variables at module load time
MISP_MODULE = os.getenv("MISP_MODULE", "127.0.0.1:6666")
QUERIES_LIMIT = int(os.getenv("QUERIES_LIMIT", "100"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Global variables
MODULES = []
IS_DEVELOPMENT = False  # Set by main.py or inferred from environment


def query_get_module(headers={"Content-type": "application/json"}):
    global MODULES
    if not MODULES:
        try:
            r = requests.get(f"http://{MISP_MODULE}/modules", headers=headers)
        except ConnectionError:
            return {"message": "Instance of misp-modules is unreachable"}
        except Exception as e:
            return {"message": str(e)}
        MODULES = r.json()
        return r.json()
    else:
        return MODULES


def query_post_query(data, headers={"Content-type": "application/json"}):
    try:
        r = requests.post(
            f"http://{MISP_MODULE}/query", data=json.dumps(data), headers=headers
        )
    except ConnectionError:
        return {"message": "Instance of misp-modules is unreachable"}
    except Exception as e:
        return {"message": str(e)}
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
    loc_path = os.path.join(parent_path, "misp-objects", "objects")
    if os.path.isdir(loc_path):
        with open(
            os.path.join(loc_path, obj_name, "definition.json"), "r"
        ) as read_json:
            loc_json = json.load(read_json)
        return loc_json
    return False


def admin_user_active():
    return bool(ADMIN_PASSWORD)


def admin_password():
    return ADMIN_PASSWORD


def gen_admin_password():
    """Generate or return admin password. Only validates in production when called explicitly."""
    if ADMIN_PASSWORD:
        return ADMIN_PASSWORD
    if IS_DEVELOPMENT:
        # Auto-generate in development mode
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@$%#[]+-:;_&*().,?0123456789"
        password = "".join(random.choice(chars) for _ in range(20))
        print(
            f"##########################\n##    Admin password    ##\n## {password} ##\n##########################"
        )
        return password
    else:
        # In production, warn but don't fail - admin login will handle validation
        print("WARNING: ADMIN_PASSWORD not set in .env - admin user will be disabled")
        return None


def get_limit_queries():
    return QUERIES_LIMIT
