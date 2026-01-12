"""
Rate Limiter Module

Prevents rapid-fire execution of security tools to avoid
overwhelming targets or triggering security measures.
"""

import asyncio
import os
import time
from collections import defaultdict
from typing import Optional

# Default minimum time between scans (seconds)
DEFAULT_RATE_LIMIT = int(os.environ.get("MCP_RATE_LIMIT", "5"))


class RateLimiter:
    """
    Rate limiter for tool execution.

    Tracks the last execution time for each target and enforces
    a minimum delay between executions.
    """

    def __init__(self, min_interval: Optional[int] = None):
        """
        Initialize the rate limiter.

        Args:
            min_interval: Minimum seconds between executions per target
        """
        self.min_interval = min_interval or DEFAULT_RATE_LIMIT
        self._last_execution: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, target: str) -> None:
        """
        Acquire permission to execute against a target.

        This will block if the rate limit hasn't been satisfied.

        Args:
            target: The target identifier (hostname/IP)
        """
        async with self._locks[target]:
            now = time.time()
            last = self._last_execution[target]
            elapsed = now - last

            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                await asyncio.sleep(wait_time)

            self._last_execution[target] = time.time()

    def time_until_available(self, target: str) -> float:
        """
        Get the time until the next execution is allowed.

        Args:
            target: The target identifier

        Returns:
            Seconds until available (0 if immediately available)
        """
        now = time.time()
        last = self._last_execution[target]
        elapsed = now - last

        if elapsed >= self.min_interval:
            return 0.0

        return self.min_interval - elapsed

    def reset(self, target: Optional[str] = None) -> None:
        """
        Reset the rate limiter.

        Args:
            target: Specific target to reset, or None to reset all
        """
        if target:
            self._last_execution.pop(target, None)
        else:
            self._last_execution.clear()


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
