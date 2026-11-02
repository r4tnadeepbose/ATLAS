"""In-process Prometheus-style counters for operational visibility."""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[str, float] = defaultdict(float)
_gauges: dict[str, float] = {}
_latencies: dict[str, list[float]] = defaultdict(list)


def incr(name: str, value: float = 1.0, **labels) -> None:
    key = _key(name, labels)
    with _lock:
        _counters[key] += value


def gauge(name: str, value: float, **labels) -> None:
    key = _key(name, labels)
    with _lock:
        _gauges[key] = value


def observe(name: str, value: float, **labels) -> None:
    key = _key(name, labels)
    with _lock:
        bucket = _latencies[key]
        bucket.append(value)
        del bucket[:-1000]


def _key(name: str, labels: dict) -> str:
    if not labels:
        return name
    label_str = ",".join(f'{key}="{value}"' for key, value in sorted(labels.items()))
    return f"{name}{{{label_str}}}"


def snapshot() -> dict:
    with _lock:
        return {
            "counters": dict(_counters),
            "gauges": dict(_gauges),
            "latency_samples": {key: len(value) for key, value in _latencies.items()},
        }
