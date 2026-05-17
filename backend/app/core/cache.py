import copy
import threading
import time
from collections.abc import Callable
from typing import TypeVar


T = TypeVar("T")

READ_CACHE_LOCK = threading.Lock()
READ_CACHE: dict[str, tuple[float, object]] = {}


def cached_read(key: str, ttl_seconds: float, factory: Callable[[], T]) -> T:
    now = time.monotonic()
    with READ_CACHE_LOCK:
        cached = READ_CACHE.get(key)
        if cached and cached[0] > now:
            return copy.deepcopy(cached[1])
    value = factory()
    with READ_CACHE_LOCK:
        READ_CACHE[key] = (now + ttl_seconds, copy.deepcopy(value))
    return value


def clear_read_cache(prefix: str = "") -> None:
    with READ_CACHE_LOCK:
        if not prefix:
            READ_CACHE.clear()
            return
        for key in list(READ_CACHE):
            if key.startswith(prefix):
                del READ_CACHE[key]
