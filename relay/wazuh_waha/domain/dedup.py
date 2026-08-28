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

    def is_duplicate(self, rule_id: str, agent_id: str) -> bool:
        state = self._cleanup(self._read_state())
        key = f"{rule_id}:{agent_id}"
        return key in state

    def mark(self, rule_id: str, agent_id: str) -> None:
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


deduper = Deduper(
    ttl=settings.relay_dedup_ttl,
    state_file=settings.dedup_state_file,
)
