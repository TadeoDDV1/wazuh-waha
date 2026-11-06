import fcntl
import json
import time
from contextlib import contextmanager
from pathlib import Path

from ..config import settings


class Deduper:
    def __init__(self, ttl: int, state_file: Path | None = None):
        self.ttl = ttl
        self._state_file = state_file or settings.dedup_state_file
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked_state(self, mode: str = "r"):
        path = self._state_file
        if mode == "r":
            if not path.exists():
                path.touch()
            fd = open(path, "rb")
        else:
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
        with self._locked_state("w") as f:
            f.seek(0)
            f.truncate()
            f.write(json.dumps(new_state).encode("utf-8"))
            f.flush()

    def _cleanup(self, state: dict) -> dict:
        now = time.time()
        return {k: ts for k, ts in state.items() if now - ts <= self.ttl}

    def _key(self, rule_id: str, agent_id: str, key_extra: str = "") -> str:
        return f"{rule_id}:{agent_id}:{key_extra}" if key_extra else f"{rule_id}:{agent_id}"

    def is_duplicate(self, rule_id: str, agent_id: str, key_extra: str = "") -> bool:
        state = self._cleanup(self._read_state())
        key = self._key(rule_id, agent_id, key_extra)
        return key in state

    def claim(self, rule_id: str, agent_id: str, key_extra: str = "") -> bool:
        """Reserva atómicamente la clave. True si no existía (y la marca).

        Check + escritura ocurren bajo el mismo lock exclusivo, así dos
        workers no pueden enviar la misma alerta a la vez.
        """
        key = self._key(rule_id, agent_id, key_extra)
        with self._locked_state("w") as f:
            state = self._cleanup(self._read_owned(f))
            if key in state:
                return False
            state[key] = time.time()
            self._write_owned(f, state)
            return True

    def release(self, rule_id: str, agent_id: str, key_extra: str = "") -> None:
        """Libera una reserva (el envío falló; se permite reintentar)."""
        key = self._key(rule_id, agent_id, key_extra)
        with self._locked_state("w") as f:
            state = self._cleanup(self._read_owned(f))
            if state.pop(key, None) is not None:
                self._write_owned(f, state)

    def mark(self, rule_id: str, agent_id: str, key_extra: str = "") -> None:
        with self._locked_state("w") as f:
            state = self._cleanup(self._read_owned(f))
            state[self._key(rule_id, agent_id, key_extra)] = time.time()
            self._write_owned(f, state)

    @staticmethod
    def _read_owned(f) -> dict:
        try:
            return json.loads(f.read().decode("utf-8") or "{}")
        except (json.JSONDecodeError, ValueError):
            return {}

    @staticmethod
    def _write_owned(f, state: dict) -> None:
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state).encode("utf-8"))
        f.flush()


deduper = Deduper(
    ttl=settings.relay_dedup_ttl,
    state_file=settings.dedup_state_file,
)
