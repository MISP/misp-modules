"""Module parser limits compatible with Flask's read-only request properties."""

from flask import Request


class ModuleRequest(Request):
    def _module_limit(self, configured_limit):
        if self.endpoint == "home.run_import":
            from .import_core import MAX_IMPORT_SIZE as input_limit
        elif self.endpoint == "home.run_export":
            from .export_core import MAX_EXPORT_SIZE as input_limit
        else:
            return configured_limit

        # Allow multipart metadata in addition to the bounded input data.
        limit = input_limit + 1024 * 1024
        return min(limit, configured_limit) if configured_limit is not None else limit

    @property
    def max_content_length(self):
        return self._module_limit(super().max_content_length)

    @property
    def max_form_memory_size(self):
        if self.endpoint == "home.run_import":
            # Pasted data can exceed Werkzeug's default form field limit.
            return self._module_limit(None)
        return super().max_form_memory_size
