"""Opt-in tracing of outbound requests without consuming streamed bodies."""

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from uuid import uuid4

LOGGER = logging.getLogger("misp-modules.http")
_MODULE = ContextVar("http_debug_module", default="unknown")
_enabled = False


@contextmanager
def module_context(module_name):
    """Associate HTTP exchanges with the module running in this worker."""
    token = _MODULE.set(module_name)
    try:
        yield
    finally:
        _MODULE.reset(token)


class _LoggedBody:
    def __init__(self, body, label):
        self.body = body
        self.label = label

    def __getattr__(self, name):
        return getattr(self.body, name)

    def __iter__(self):
        for chunk in self.body:
            LOGGER.debug("%s request body chunk: %r", self.label, chunk)
            yield chunk


class _LoggedFile(_LoggedBody):
    def read(self, *args, **kwargs):
        chunk = self.body.read(*args, **kwargs)
        LOGGER.debug("%s request body chunk: %r", self.label, chunk)
        return chunk


def _trace_response_body(raw, label):
    """Log bytes only when the caller reads them, including chunked responses."""

    def trace_read(read):
        @wraps(read)
        def logged_read(*args, **kwargs):
            try:
                chunk = read(*args, **kwargs)
            except Exception:
                LOGGER.debug("%s response body read failed", label, exc_info=True)
                raise
            LOGGER.debug("%s response body chunk: %r", label, chunk)
            return chunk

        return logged_read

    for name in ("read", "read1"):
        if hasattr(raw, name):
            setattr(raw, name, trace_read(getattr(raw, name)))

    if hasattr(raw, "read_chunked"):
        read_chunked = raw.read_chunked

        @wraps(read_chunked)
        def logged_read_chunked(*args, **kwargs):
            try:
                for chunk in read_chunked(*args, **kwargs):
                    LOGGER.debug("%s response body chunk: %r", label, chunk)
                    yield chunk
            except Exception:
                LOGGER.debug("%s response body read failed", label, exc_info=True)
                raise

        raw.read_chunked = logged_read_chunked


def configure_http_debug(enabled=False):
    """Enable tracing for requests and SDKs using its standard HTTP adapter.

    Install before importing modules so existing and future sessions are covered.
    Headers and bodies are intentionally unredacted and untruncated.
    """
    global _enabled
    _enabled = enabled
    if not enabled:
        return

    from requests.adapters import HTTPAdapter

    if getattr(HTTPAdapter.send, "_misp_http_debug", False) is True:
        return

    send = HTTPAdapter.send

    @wraps(send)
    def logged_send(adapter, request, *args, **kwargs):
        if not _enabled:
            return send(adapter, request, *args, **kwargs)

        label = f"HTTP {uuid4().hex} module={_MODULE.get()}"
        LOGGER.debug("%s request: %s %s\nHeaders: %r", label, request.method, request.url, dict(request.headers))
        body = request.body
        if hasattr(body, "read"):
            request.body = _LoggedFile(body, label)
        elif body is not None and not isinstance(body, (str, bytes, bytearray, memoryview)):
            request.body = _LoggedBody(body, label)
        else:
            LOGGER.debug("%s request body: %r", label, bytes(body) if isinstance(body, memoryview) else body)

        try:
            response = send(adapter, request, *args, **kwargs)
        except Exception:
            LOGGER.debug("%s request failed", label, exc_info=True)
            raise
        finally:
            request.body = body

        LOGGER.debug(
            "%s response: %s %s\nHeaders: %r", label, response.status_code, response.reason, dict(response.headers)
        )
        _trace_response_body(response.raw, label)
        return response

    logged_send._misp_http_debug = True
    HTTPAdapter.send = logged_send
