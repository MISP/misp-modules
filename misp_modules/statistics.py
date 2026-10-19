"""Bounded, process-local statistics for module queries; no payloads are retained."""

import datetime
import threading
import time
from dataclasses import dataclass, field
from typing import Mapping

# Cumulative upper bounds in seconds. The final bucket includes every response.
LATENCY_BUCKETS = (0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class _Counters:
    queries: int = 0
    completed: int = 0
    successes: int = 0
    module_errors: int = 0
    exceptions: int = 0
    timeouts: int = 0
    request_bytes: int = 0
    response_bytes: int = 0
    duration_total: float = 0.0
    duration_min: float | None = None
    duration_max: float | None = None
    duration_last: float | None = None
    last_query_at: str | None = None
    last_completed_at: str | None = None
    buckets: list[int] = field(default_factory=lambda: [0] * len(LATENCY_BUCKETS))

    def start(self, request_bytes: int, timestamp: str) -> None:
        self.queries += 1
        self.request_bytes += request_bytes
        self.last_query_at = timestamp

    def finish(self, outcome: str, duration: float, response_bytes: int, timestamp: str) -> None:
        self.completed += 1
        setattr(self, outcome, getattr(self, outcome) + 1)
        self.response_bytes += response_bytes
        self.duration_total += duration
        self.duration_min = duration if self.duration_min is None else min(self.duration_min, duration)
        self.duration_max = duration if self.duration_max is None else max(self.duration_max, duration)
        self.duration_last = duration
        self.last_completed_at = timestamp
        for index, bound in enumerate(LATENCY_BUCKETS):
            if duration <= bound:
                self.buckets[index] += 1

    def snapshot(self) -> dict:
        errors = self.module_errors + self.exceptions + self.timeouts
        return {
            "queries": self.queries,
            "completed": self.completed,
            "in_flight": self.queries - self.completed,
            "successes": self.successes,
            "errors": errors,
            "module_errors": self.module_errors,
            "exceptions": self.exceptions,
            "timeouts": self.timeouts,
            "success_rate": self.successes / self.completed if self.completed else None,
            "error_rate": errors / self.completed if self.completed else None,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "last_query_at": self.last_query_at,
            "last_completed_at": self.last_completed_at,
            "response_time_seconds": {
                "count": self.completed,
                "total": self.duration_total,
                "min": self.duration_min,
                "max": self.duration_max,
                "average": self.duration_total / self.completed if self.completed else None,
                "last": self.duration_last,
                "buckets": {
                    **{str(bound): count for bound, count in zip(LATENCY_BUCKETS, self.buckets)},
                    "+Inf": self.completed,
                },
            },
        }


class ModuleStatistics:
    """Collect one outcome per query, independently of worker completion after a timeout."""

    def __init__(self) -> None:
        self.started_at = _utc_now()
        self._started = time.perf_counter()
        self._lock = threading.Lock()
        self._modules: dict[str, _Counters] = {}
        self._totals = _Counters()

    def start(self, module_name: str, request_bytes: int) -> float:
        with self._lock:
            started = time.perf_counter()
            timestamp = _utc_now()
            self._modules.setdefault(module_name, _Counters()).start(request_bytes, timestamp)
            self._totals.start(request_bytes, timestamp)
            return started

    def finish(self, module_name: str, started: float, outcome: str, response_bytes: int) -> None:
        with self._lock:
            duration = time.perf_counter() - started
            timestamp = _utc_now()
            self._modules[module_name].finish(outcome, duration, response_bytes, timestamp)
            self._totals.finish(outcome, duration, response_bytes, timestamp)

    def snapshot(self, module_types: Mapping[str, str]) -> dict:
        with self._lock:
            return {
                "started_at": self.started_at,
                "uptime_seconds": time.perf_counter() - self._started,
                "totals": self._totals.snapshot(),
                "modules": {
                    name: {"type": module_type, **self._modules.get(name, _Counters()).snapshot()}
                    for name, module_type in sorted(module_types.items())
                },
            }
