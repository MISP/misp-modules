"""Build import requests using the module daemon's advertised capabilities."""

import base64
import json

from werkzeug.utils import secure_filename

from . import home_core as HomeModel

MAX_IMPORT_SIZE = 20 * 1024 * 1024


def build_import_request(form, files):
    modules = HomeModel.get_modules(("import",))
    if not isinstance(modules, list):
        raise ValueError(modules.get("message", "Unable to load import modules."))
    module = next((m for m in modules if m["name"] == form.get("module")), None)
    if not module:
        raise ValueError("Select an active import module.")

    try:
        config = json.loads(form.get("config", "{}"))
    except (ValueError, TypeError):
        raise ValueError("Module configuration must be a JSON object.") from None
    if not isinstance(config, dict):
        raise ValueError("Module configuration must be a JSON object.")

    attributes = module["mispattributes"]
    user_config = attributes.get("userConfig", {})
    allowed = set(module["meta"].get("config", [])) | set(user_config)
    if set(config) - allowed or any(
        not isinstance(v, (str, int, bool)) for v in config.values()
    ):
        raise ValueError("Unknown or invalid module configuration.")
    for key, field in user_config.items():
        default = "1" if str(field.get("checked", False)).lower() == "true" else "0"
        value = config.get(key, default if field["type"] == "Boolean" else "")
        if field.get("required") and str(value).strip() == "":
            raise ValueError(f"Enter a value for {key}.")
        if field["type"] == "Boolean":
            if value not in (True, False, 1, 0, "1", "0"):
                raise ValueError(f"{key} must be a boolean.")
            value = "1" if value in (True, 1, "1") else "0"
        elif field["type"] == "Integer" and str(value).strip():
            try:
                value = str(int(str(value)))
            except ValueError:
                raise ValueError(f"{key} must be an integer.") from None
        config[key] = str(value)

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
