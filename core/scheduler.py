"""Helpers for threaded and async task orchestration."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable


class ScanScheduler:
    """Lightweight scheduler used by services and orchestration code."""

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers

    def run_threaded(self, tasks: Dict[str, Callable[[], Any]]):
        """Run named callables in a thread pool and collect results."""
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(task): task_name
                for task_name, task in tasks.items()
            }
            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    results[task_name] = future.result()
                except Exception as exc:  # pragma: no cover - defensive wrapper
                    results[task_name] = {"error": str(exc)}
        return results

    async def run_async(self, coroutines: Iterable[Any]):
        """Run async tasks concurrently and preserve exceptions in results."""
        return await asyncio.gather(*coroutines, return_exceptions=True)
