"""Registro de tareas en segundo plano.

`asyncio.create_task()` sin guardar la referencia deja que el recolector de
basura cancele tareas a medio camino y pierde las excepciones. Este módulo
mantiene referencias fuertes hasta que terminan y registra sus errores.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Coroutine

log = logging.getLogger("wazuh-waha.tasks")
_tasks: set[asyncio.Task[Any]] = set()


def _on_done(task: asyncio.Task[Any]) -> None:
    _tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("background_task_failed name=%s err=%r", task.get_name(), exc, exc_info=exc)


def spawn(coro: Coroutine[Any, Any, Any], *, name: str | None = None) -> asyncio.Task[Any] | None:
    """Lanza una corrutina en segundo plano conservando su referencia."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Sin event loop no se puede ejecutar; cerrar la corrutina evita warnings.
        coro.close()
        log.warning("spawn_without_loop name=%s", name)
        return None
    task = loop.create_task(coro, name=name)
    _tasks.add(task)
    task.add_done_callback(_on_done)
    return task


async def shutdown(timeout: float = 5.0) -> None:
    """Espera (con límite) a que terminen las tareas pendientes."""
    if not _tasks:
        return
    done, pending = await asyncio.wait(list(_tasks), timeout=timeout)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
