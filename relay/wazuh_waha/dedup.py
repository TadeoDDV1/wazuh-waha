"""
Deduplicacion: si la misma (rule_id, agent_id) llega dentro de la ventana TTL,
se descarta. Persiste en disco para sobrevivir restarts Y para coordinar entre
workers uvicorn.

MULTI-WORKER SAFETY:
  uvicorn --workers N fork-ea N procesos, cada uno con su propia memoria.
  Para que el dedup funcione con varios workers, usamos fcntl.flock
  (file lock advisory del kernel) alrededor de read-modify-write del JSON.
  Solo un worker a la vez puede escribir; los demas esperan con LOCK_SH
  para leer la version actualizada.
"""
import fcntl
import json
import time
from contextlib import contextmanager
from pathlib import Path

from .config import settings


class Deduper:
    def __init__(self, ttl: int, state_file: Path | None = None):
        self.ttl = ttl
        self._state_file = state_file or settings.dedup_state_file
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked_state(self, mode: str = "r"):
        """
        Context manager: abre el JSON con un file lock.
        - mode='r': LOCK_SH (compartido, varios readers OK).
        - mode='w': LOCK_EX (exclusivo, un writer a la vez).
        Si el archivo no existe, lo crea vacio (lockeado atomicamente).
        """
        path = self._state_file
        if mode == "r":
            # Si no existe, retornar fd vacio (read devuelve {})
            if not path.exists():
                path.touch()
            fd = open(path, "rb")
        else:
            # En modo write, crear el archivo si no existe
            if not path.exists():
                path.touch()
            fd = open(path, "rb+")
        try:
            if mode == "r":
                fcntl.flock(fd.fileno(), fcntl.LOCK_SH)
            else:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            yield fd
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            fd.close()

    def _read_state(self) -> dict:
        if not self._state_file.exists():
            return {}
        try:
            with self._locked_state("r") as f:
                return json.loads(f.read().decode("utf-8") or "{}")
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write_state(self, new_state: dict) -> None:
        # LOCK_EX exclusivo: solo un writer a la vez.
        with self._locked_state("w") as f:
            f.seek(0)
            f.truncate()
            f.write(json.dumps(new_state).encode("utf-8"))
            f.flush()

    def _cleanup(self, state: dict) -> dict:
        now = time.time()
        return {k: ts for k, ts in state.items() if now - ts <= self.ttl}

    def is_duplicate(self, rule_id: str, agent_id: str) -> bool:
        state = self._cleanup(self._read_state())
        key = f"{rule_id}:{agent_id}"
        return key in state

    def mark(self, rule_id: str, agent_id: str) -> None:
        # Read-modify-write bajo LOCK_EX para serializar entre workers.
        with self._locked_state("w") as f:
            try:
                state = json.loads(f.read().decode("utf-8") or "{}")
            except (json.JSONDecodeError, ValueError):
                state = {}
            state = self._cleanup(state)
            state[f"{rule_id}:{agent_id}"] = time.time()
            f.seek(0)
            f.truncate()
            f.write(json.dumps(state).encode("utf-8"))
            f.flush()


# Singleton (uno por proceso, no por worker, lo cual es lo que queremos).
deduper = Deduper(
    ttl=settings.relay_dedup_ttl,
    state_file=settings.dedup_state_file,
)
