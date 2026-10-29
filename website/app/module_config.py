"""Validate per-run options advertised by import and export modules."""

import json


def build_module_config(module, raw_config):
    try:
        config = json.loads(raw_config)
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

    return config
