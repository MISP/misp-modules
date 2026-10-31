"""Opt-in, bounded, process-local caching for module query results."""

import hmac
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from pathlib import Path

import orjson


class CacheConfigError(ValueError):
    """Invalid cache configuration, safe to report without configuration values."""


class _ModuleCache:
    def __init__(self, ttl_seconds=300, max_entries=128, max_bytes=16777216):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.entries = OrderedDict()
        self.pending = {}
        self.response_bytes = 0
        self.lock = threading.Lock()
        self.counters = dict.fromkeys(("hits", "misses", "coalesced", "stores", "evictions", "expired", "skipped"), 0)

    def _expire(self):
        now = time.monotonic()
        for key, (expires, body) in list(self.entries.items()):
            if expires <= now:
                del self.entries[key]
                self.response_bytes -= len(body)
                self.counters["expired"] += 1

    def run(self, key, execute, deadline):
        with self.lock:
            self._expire()
            if key in self.entries:
                self.counters["hits"] += 1
                self.entries.move_to_end(key)
                return self.entries[key][1], "successes"
            future = self.pending.get(key)
            leader = future is None
            if leader:
                self.counters["misses"] += 1
                future = self.pending[key] = Future()
            else:
                self.counters["coalesced"] += 1

        # Never hold a cache lock during a module call or while waiting for one.
        if not leader:
            return future.result()
        try:
            result = execute()
            body, outcome = result
            with self.lock:
                now = time.monotonic()
                if (
                    outcome == "successes"
                    and body != b"null"
                    and len(body) <= self.max_bytes
                    and (deadline is None or now < deadline)
                ):
                    self._expire()
                    while self.entries and (
                        len(self.entries) >= self.max_entries or self.response_bytes + len(body) > self.max_bytes
                    ):
                        _, (_, evicted) = self.entries.popitem(last=False)
                        self.response_bytes -= len(evicted)
                        self.counters["evictions"] += 1
                    self.entries[key] = (now + self.ttl_seconds, body)
                    self.response_bytes += len(body)
                    self.counters["stores"] += 1
                else:
                    self.counters["skipped"] += 1
        except BaseException as exc:
            future.set_exception(exc)
            raise
        else:
            future.set_result(result)
            return result
        finally:
            with self.lock:
                del self.pending[key]

    def snapshot(self):
        with self.lock:
            self._expire()
            return {
                "ttl_seconds": self.ttl_seconds,
                "max_entries": self.max_entries,
                "max_bytes": self.max_bytes,
                "entries": len(self.entries),
                "response_bytes": self.response_bytes,
                "in_flight": len(self.pending),
                **self.counters,
                "saved_queries": self.counters["hits"] + self.counters["coalesced"],
            }


class ModuleCache:
    """No modules are cached unless explicitly enabled in a supplied file."""

    def __init__(self):
        self._modules = {}
        self._secret = b""

    @classmethod
    def from_file(cls, path):
        try:
            contents = Path(path).read_bytes()
        except OSError:
            raise CacheConfigError("Unable to read cache configuration file") from None
        try:
            document = orjson.loads(contents)
        except orjson.JSONDecodeError:
            raise CacheConfigError("Cache configuration file must contain valid JSON") from None
        if not isinstance(document, dict) or set(document) != {"version", "modules"}:
            raise CacheConfigError("Cache configuration must contain only 'version' and 'modules'")
        if type(document["version"]) is not int or document["version"] != 1:
            raise CacheConfigError("Unsupported cache configuration version; expected 1")
        if not isinstance(document["modules"], dict):
            raise CacheConfigError("Cache configuration 'modules' must be an object")

        instance = cls()
        for name, settings in document["modules"].items():
            if not name or name.startswith("type:"):
                raise CacheConfigError("Cache configuration requires nonempty, non-reserved module names")
            if not isinstance(settings, dict) or set(settings) - {"enabled", "ttl_seconds", "max_entries", "max_bytes"}:
                raise CacheConfigError("Invalid per-module cache settings")
            if type(settings.get("enabled", False)) is not bool:
                raise CacheConfigError("Cache 'enabled' must be a boolean")
            limits = {key: value for key, value in settings.items() if key != "enabled"}
            if any(type(value) is not int or value <= 0 for value in limits.values()):
                raise CacheConfigError("Cache limits must be positive integers")
            if settings.get("enabled", False):
                instance._modules[name] = _ModuleCache(**limits)
        if instance._modules:
            instance._secret = secrets.token_bytes(32)
        return instance

    def validate_modules(self, handlers):
        """Prevent accidentally skipping action, import, or export invocations."""
        for name in self._modules:
            if name in handlers and handlers.get(f"type:{name}") != "expansion":
                raise CacheConfigError("Caching may only be enabled for expansion modules")

    def enabled_for(self, module_name):
        return module_name in self._modules

    def run(self, module_name, payload, execute, deadline=None):
        cache = self._modules.get(module_name)
        if cache is None:
            return execute()
        # Include the entire effective payload, including credentials, endpoint,
        # attribute UUIDs and options. Store only a process-keyed digest as key.
        key = hmac.digest(self._secret, orjson.dumps(payload, option=orjson.OPT_SORT_KEYS), "sha256")
        return cache.run(key, execute, deadline)

    def snapshot(self, module_types):
        return {
            name: cache.snapshot()
            for name, cache in sorted(self._modules.items())
            if module_types.get(name) == "expansion"
        }
