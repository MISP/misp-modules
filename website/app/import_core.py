"""Build import requests using the module daemon's advertised capabilities."""

import base64

from werkzeug.utils import secure_filename

from . import home_core as HomeModel
from .module_config import build_module_config

MAX_IMPORT_SIZE = 20 * 1024 * 1024


def build_import_request(form, files):
    modules = HomeModel.get_modules(("import",))
    if not isinstance(modules, list):
        raise ValueError(modules.get("message", "Unable to load import modules."))
    module = next((m for m in modules if m["name"] == form.get("module")), None)
    if not module:
        raise ValueError("Select an active import module.")

    config = build_module_config(module, form.get("config", "{}"))
    attributes = module["mispattributes"]

    sources = attributes.get("inputSource", [])
    source = form.get("source", "config")
    payload = {}
    label = module["name"]
    if sources:
        if source not in sources or source not in ("file", "paste"):
            raise ValueError("Choose an input source supported by this module.")
        if source == "file":
            upload = files.get("file")
            if not upload or not upload.filename:
                raise ValueError("Choose a file to import.")
            data = upload.read(MAX_IMPORT_SIZE + 1)
            label = secure_filename(upload.filename) or "import-data"
        else:
            data = form.get("data", "").encode("utf-8")
            label = "Pasted data"
        if not data:
            raise ValueError("Import data cannot be empty.")
        if len(data) > MAX_IMPORT_SIZE:
            raise ValueError("Import data must be at most 20 MiB.")
        payload = {"data": base64.b64encode(data).decode("ascii"), "filename": label}
    elif source != "config":
        raise ValueError("This module uses configuration only.")

    return {
        "query": [label],
        "input": "import",
        "modules": [module["name"]],
        "config": {module["name"]: config},
        "parent_id": "",
    }, payload
