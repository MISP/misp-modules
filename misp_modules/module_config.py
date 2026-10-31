"""Optional, server-local defaults for module request configuration."""

from copy import deepcopy
from pathlib import Path

import orjson


class ModuleConfigError(ValueError):
    """Invalid local configuration, with a message safe to show at startup."""


class ModuleConfig:
    """Load defaults once and resolve them without sharing mutable request state."""

    def __init__(self):
        self._modules = {}

    @classmethod
    def from_file(cls, path: str) -> "ModuleConfig":
        """Read and validate a versioned JSON file without exposing its values."""
        try:
            contents = Path(path).read_bytes()
        except OSError:
            raise ModuleConfigError("Unable to read module configuration file") from None
        try:
            document = orjson.loads(contents)
        except orjson.JSONDecodeError:
            raise ModuleConfigError("Module configuration file must contain valid JSON") from None

        if not isinstance(document, dict) or set(document) != {"version", "modules"}:
            raise ModuleConfigError("Module configuration must contain only 'version' and 'modules'")
        if type(document["version"]) is not int or document["version"] != 1:
            raise ModuleConfigError("Unsupported module configuration version; expected 1")
        if not isinstance(document["modules"], dict):
            raise ModuleConfigError("Module configuration 'modules' must be an object")

        for name, settings in document["modules"].items():
            if not name or name.startswith("type:"):
                raise ModuleConfigError("Module configuration requires nonempty, non-reserved module names")
            if (
                not isinstance(settings, dict)
                or "config" not in settings
                or set(settings) - {"config", "fallback_when_empty"}
            ):
                raise ModuleConfigError("Each module must contain 'config' and optionally 'fallback_when_empty'")
            config = settings["config"]
            if not isinstance(config, dict) or any(not key for key in config):
                raise ModuleConfigError("Each module 'config' must be an object with nonempty keys")
            fallback = settings.get("fallback_when_empty", [])
            if not isinstance(fallback, list) or any(not isinstance(key, str) or key not in config for key in fallback):
                raise ModuleConfigError("'fallback_when_empty' must be a list of keys present in the module's 'config'")

        instance = cls()
        instance._modules = document["modules"]
        return instance

    def resolve(self, module_name: str, payload: dict) -> dict:
        """Fill missing settings; preserve explicit empty values unless opted in.

        Return the original payload when nothing applies, preserving the original
        JSON bytes for legacy handlers. Malformed API config remains the module's
        responsibility, as before.
        """
        settings = self._modules.get(module_name)
        if not settings:
            return payload
        config = payload.get("config", {})
        if not isinstance(config, dict):
            return payload
        fallback = settings.get("fallback_when_empty", [])
        defaults = {
            key: value
            for key, value in settings["config"].items()
            if key not in config or (key in fallback and (config[key] is None or config[key] == ""))
        }
        if not defaults:
            return payload
        resolved = deepcopy(payload)
        resolved.setdefault("config", {}).update(deepcopy(defaults))
        return resolved
