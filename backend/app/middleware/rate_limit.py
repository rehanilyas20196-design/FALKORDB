
"""
GraphGuard AI - API Rate Limiting Middleware.

Provides an in-memory, per-client rate limiter for FastAPI.

Important:
- Suitable for local development and single-process demos.
- Limits are reset if the server restarts.
- Multiple workers or servers do not share counters.
- For production or distributed deployments, use a shared
  store such as Redis.
"""

import logging
import os
import time

from collections import defaultdict, deque
from threading import Lock
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


logger = logging.getLogger("graphguard.rate_limit")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Apply a sliding-window request limit per client IP address.

    Environment variables:
        RATE_LIMIT_REQUESTS: Maximum requests in the time window.
        RATE_LIMIT_WINDOW_SECONDS: Window duration in seconds.
        RATE_LIMIT_EXEMPT_PATHS: Comma-separated paths to exempt.
    """

    def __init__(
        self,
        app,
        requests_per_window: int | None = None,
        window_seconds: int | None = None,
        exempt_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)

        self.requests_per_window = (
            requests_per_window
            if requests_per_window is not None
            else int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
        )

        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
        )

        if self.requests_per_window < 1:
            raise ValueError("requests_per_window must be at least 1")

        if self.window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        configured_exempt_paths = os.getenv(
            "RATE_LIMIT_EXEMPT_PATHS",
            "/docs,/redoc,/openapi.json",
        )

        self.exempt_paths = (
            set(exempt_paths)
            if exempt_paths is not None
            else {
                path.strip()
                for path in configured_exempt_paths.split(",")
                if path.strip()
            }
        )

        # Store request timestamps for each client.
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    @staticmethod
    def _get_client_key(request: Request) -> str:
        """
        Return a client identifier.

        Uses the ASGI client's IP address. Do not blindly trust
        X-Forwarded-For headers unless a trusted proxy is configured.
        """
        if request.client and request.client.host:
            return request.client.host

        return "unknown"

    def _check_rate_limit(self, client_key: str) -> tuple[bool, int]:
        """
        Return (allowed, retry_after_seconds).

        Uses a sliding window so requests are counted over the
        preceding window_seconds interval.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._requests[client_key]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.requests_per_window:
                retry_after = max(
                    1,
                    int(timestamps[0] + self.window_seconds - now + 0.999),
                )
                return False, retry_after

            timestamps.append(now)

            return True, 0

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        # OPTIONS requests are commonly used for browser CORS preflight.
        if request.method == "OPTIONS":
            return await call_next(request)

        if request.url.path in self.exempt_paths:
            return await call_next(request)

        client_key = self._get_client_key(request)
        allowed, retry_after = self._check_rate_limit(client_key)

        if not allowed:
            logger.warning(
                "Rate limit exceeded: client=%s path=%s",
                client_key,
                request.url.path,
            )

            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": (
                        "Too many requests. Please wait before "
                        "trying again."
                    ),
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.requests_per_window),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # These headers describe the configured limit. The remaining
        # value is an approximation if concurrent requests are active.
        with self._lock:
            timestamps = self._requests.get(client_key, deque())
            remaining = max(
                0,
                self.requests_per_window - len(timestamps),
            )

        response.headers["X-RateLimit-Limit"] = str(
            self.requests_per_window
        )
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response


def get_rate_limit_middleware():
    """
    Return the middleware class for FastAPI's add_middleware().

    Example:
        app.add_middleware(
            RateLimitMiddleware,
            requests_per_window=100,
            window_seconds=60,
        )
    """
    return RateLimitMiddleware
