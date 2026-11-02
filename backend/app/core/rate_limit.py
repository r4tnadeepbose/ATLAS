import threading
import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    """Fixed-window limiter suitable for a single process.

    In a multi-replica deployment this is replaced by the Redis-backed limiter
    configured in ``ATLAS_REDIS_URL``. It is deliberately conservative: each
    key tracks 60-second buckets.
    """

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        now = time.time()
        window_start = now - 60
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < window_start:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = max(1, int(60 - (now - bucket[0])))
                return False, 0, retry_after
            bucket.append(now)
            return True, self.limit - len(bucket), 0
