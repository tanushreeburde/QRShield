import time
from collections import defaultdict, deque
from threading import Lock
from typing import Tuple
from app.config import settings


class InMemoryRateLimiter:
    def __init__(self, requests_per_minute: int = 30):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60.0
        self.clients = defaultdict(deque)
        self.lock = Lock()

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        now = time.time()
        window_start = now - self.window_seconds

        with self.lock:
            queue = self.clients[client_ip]

            # Remove timestamps outside the sliding window
            while queue and queue[0] < window_start:
                queue.popleft()

            if len(queue) >= self.requests_per_minute:
                # Rate limit exceeded. Calculate retry-after seconds
                retry_after = int(queue[0] + self.window_seconds - now) + 1
                return False, max(1, retry_after)

            queue.append(now)
            return True, 0

    def reset(self):
        with self.lock:
            self.clients.clear()


rate_limiter = InMemoryRateLimiter(requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)
