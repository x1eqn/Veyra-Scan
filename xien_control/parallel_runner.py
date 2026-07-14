from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar


T = TypeVar("T")
R = TypeVar("R")


def default_worker_count(total_items: int) -> int:
    if total_items <= 1:
        return 1
    cpu = os.cpu_count() or 4
    return max(2, min(8, cpu, total_items))


def run_parallel(
    items: Iterable[T],
    worker: Callable[[T], R],
    max_workers: int | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    error_handler: Callable[[T, Exception], R] | None = None,
) -> list[R]:
    values = list(items)
    total = len(values)
    if total == 0:
        return []
    workers = max_workers or default_worker_count(total)
    if workers <= 1:
        out = []
        for index, item in enumerate(values, 1):
            if progress:
                progress(index - 1, total, _label(item))
            try:
                out.append(worker(item))
            except Exception as exc:  # noqa: BLE001
                if error_handler is None:
                    raise
                out.append(error_handler(item, exc))
        if progress:
            progress(total, total, "deep analysis complete")
        return out
    try:
        out: list[R] = []
        done = 0
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="xien-analysis") as executor:
            futures = {executor.submit(worker, item): item for item in values}
            for future in as_completed(futures):
                try:
                    out.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    if error_handler is None:
                        raise
                    out.append(error_handler(futures[future], exc))
                done += 1
                if progress:
                    progress(done, total, _label(futures[future]))
        return out
    except Exception:
        out = []
        for index, item in enumerate(values, 1):
            if progress:
                progress(index - 1, total, _label(item))
            try:
                out.append(worker(item))
            except Exception as exc:  # noqa: BLE001
                if error_handler is None:
                    raise
                out.append(error_handler(item, exc))
        if progress:
            progress(total, total, "deep analysis complete")
        return out


def _label(item: object) -> str:
    return getattr(item, "file_name", str(item))
