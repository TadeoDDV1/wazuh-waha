"""
traffic_journal.py — Journal JSONL compartido entre workers uvicorn.

Cada evento de tráfico se append-ea bajo fcntl.flock para que /tail y el
broadcast SSE sean consistentes con --workers N (el estado en memoria no se
comparte entre procesos).
"""

from __future__ import annotations

import fcntl
import json
import logging
from collections import deque
from pathlib import Path
from typing import Any, Iterator

_log = logging.getLogger("wazuh-waha.traffic.journal")

# Rotación simple: si el journal supera este tamaño, se renombra a .old
_MAX_JOURNAL_BYTES = 10 * 1024 * 1024  # 10 MiB


class TrafficJournal:
    def __init__(self, path: Path, max_memory_tail: int = 400) -> None:
        self.path = Path(path)
        self.max_memory_tail = max_memory_tail
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_file(self) -> None:
        if not self.path.exists():
            self.path.touch()

    def _maybe_rotate(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > _MAX_JOURNAL_BYTES:
                old = self.path.with_suffix(self.path.suffix + ".old")
                self.path.replace(old)
                _log.info("traffic_journal_rotated path=%s -> %s", self.path, old)
        except OSError as e:
            _log.warning("traffic_journal_rotate_error err=%s", e)

    def append(self, event: dict[str, Any]) -> None:
        """Append un evento JSON al journal de forma multi-proceso segura."""
        self._ensure_file()
        self._maybe_rotate()
        line = json.dumps(event, ensure_ascii=False, default=str) + "\n"
        with open(self.path, "a", encoding="utf-8") as fd:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            try:
                fd.write(line)
                fd.flush()
            finally:
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        """Últimos N eventos del journal (orden cronológico ascendente)."""
        self._ensure_file()
        try:
            with open(self.path, "rb") as fd:
                fcntl.flock(fd.fileno(), fcntl.LOCK_SH)
                try:
                    # Leer solo el sufijo del archivo para no cargar 10MiB
                    fd.seek(0, 2)
                    size = fd.tell()
                    chunk_size = min(size, 512 * 1024)
                    fd.seek(size - chunk_size)
                    raw = fd.read()
                finally:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        except FileNotFoundError:
            return []

        lines = raw.decode("utf-8", errors="ignore").splitlines()
        # Si el chunk cortó la primera línea parcial, descartarla (salvo si es todo el file)
        if size > chunk_size and lines:
            lines = lines[1:]
        items: deque[dict[str, Any]] = deque(maxlen=max(limit, 1))
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(items)[-limit:] if limit > 0 else list(items)

    def open_for_follow(self) -> tuple[Any, int]:
        """Abre el journal y devuelve (file_obj, offset_inicial=fin) para tailing."""
        self._ensure_file()
        fd = open(self.path, "rb")
        # Pre-poblar desde el final; el caller lee el tail inicial aparte
        fd.seek(0, 2)
        offset = fd.tell()
        return fd, offset

    @staticmethod
    def read_new_lines(fd: Any, offset: int) -> tuple[int, list[str]]:
        """Lee desde offset hasta la última línea completa (\n)."""
        try:
            fd.seek(offset)
            data = fd.read()
        except (OSError, ValueError):
            return offset, []
        if not data:
            return offset, []
        last_nl = data.rfind(b"\n")
        if last_nl < 0:
            return offset, []
        complete = data[: last_nl + 1]
        new_offset = offset + len(complete)
        lines: list[str] = []
        for line in complete.split(b"\n"):
            if line.strip():
                lines.append(line.decode("utf-8", errors="ignore"))
        return new_offset, lines


_journal: TrafficJournal | None = None


def get_journal(path: Path | None = None) -> TrafficJournal:
    global _journal
    if _journal is None:
        if path is None:
            from ..config import settings

            path = settings.traffic_journal_file
        _journal = TrafficJournal(path)
    return _journal
