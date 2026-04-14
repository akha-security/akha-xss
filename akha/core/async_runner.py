"""Shared asyncio runner for AKHA async modules."""

import asyncio
import threading
import logging
from concurrent.futures import Future
from typing import Any, Callable, Dict


logger = logging.getLogger("akha.async_runner")


class AsyncRunner:
    """Singleton shared asyncio event loop for all async modules."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._loop = asyncio.new_event_loop()
                obj._semaphores: Dict[str, asyncio.Semaphore] = {}
                obj._semaphore_limits: Dict[str, int] = {}
                obj._thread = threading.Thread(
                    target=obj._loop.run_forever,
                    daemon=True,
                    name="akha-async-runner",
                )
                obj._thread.start()
                cls._instance = obj
        return cls._instance

    def run(self, coro: Any, timeout: float = None):
        """Run a coroutine from sync code and return its result."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def submit(self, coro: Any) -> Future:
        """Submit coroutine without waiting for completion."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    async def _run_with_semaphore(self, name: str, limit: int, coro: Any):
        """Run coroutine under a named shared semaphore on the event loop."""
        normalized_limit = max(1, int(limit))
        sem = self._semaphores.get(name)
        current_limit = self._semaphore_limits.get(name)
        if sem is None or current_limit != normalized_limit:
            sem = asyncio.Semaphore(normalized_limit)
            self._semaphores[name] = sem
            self._semaphore_limits[name] = normalized_limit

        async with sem:
            return await coro

    def run_limited(self, name: str, limit: int, coro: Any, timeout: float = None):
        """Run coroutine result with shared concurrency guard and optional timeout."""
        wrapped = self._run_with_semaphore(name, limit, coro)
        return self.run(wrapped, timeout=timeout)

    async def _retry_async(
        self,
        coro_factory: Callable[[], Any],
        retries: int = 3,
        delay_seconds: float = 0.2,
    ):
        """Execute coroutine factory with bounded retries on failure."""
        attempts = max(1, int(retries))
        last_exc = None
        for attempt in range(attempts):
            try:
                return await coro_factory()
            except Exception as exc:
                last_exc = exc
                if attempt >= attempts - 1:
                    break
                await asyncio.sleep(max(0.0, float(delay_seconds)))
        logger.debug("Async retry exhausted", exc_info=True)
        raise last_exc

    def run_with_retry(
        self,
        coro_factory: Callable[[], Any],
        retries: int = 3,
        delay_seconds: float = 0.2,
        timeout: float = None,
    ):
        """Run coroutine factory with retries from sync code."""
        wrapped = self._retry_async(
            coro_factory=coro_factory,
            retries=retries,
            delay_seconds=delay_seconds,
        )
        return self.run(wrapped, timeout=timeout)

    def run_limited_with_retry(
        self,
        *,
        name: str,
        limit: int,
        coro_factory: Callable[[], Any],
        retries: int = 3,
        delay_seconds: float = 0.2,
        timeout: float = None,
    ):
        """Run coroutine with both semaphore limiting and retry logic."""

        async def _factory_wrapped():
            return await self._run_with_semaphore(name, limit, coro_factory())

        return self.run_with_retry(
            coro_factory=_factory_wrapped,
            retries=retries,
            delay_seconds=delay_seconds,
            timeout=timeout,
        )

    def get_loop(self) -> asyncio.AbstractEventLoop:
        return self._loop
