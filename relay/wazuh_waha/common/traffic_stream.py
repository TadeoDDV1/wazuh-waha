"""
traffic_stream.py — Lector y difusor de TODO el tráfico/alertas de Wazuh.

Fuentes configurables (settings.traffic_source):
  auto  → local si alerts.json existe; si no, SSH a la VM; si no, API manager
  local → tail de alerts.json local (útil si el manager corre en este host)
  ssh   → poll de alerts.json en la VM manager vía SSH
  api   → poll de la API del manager (:55000) / vía endpoint de alertas
  off   → solo inyecciones manuales (alerts.py / simulate)

Multi-worker: los eventos se append-ean a traffic.jsonl (flock) y cada worker
hace tail de ese journal para broadcast SSE + ring buffer local.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from .traffic_journal import get_journal

_log = logging.getLogger("wazuh-waha.traffic")


def normalize_wazuh_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza un evento en formato estándar para la terminal y telemetría."""
    rule = raw.get("rule", {}) or {}
    data = raw.get("data", {}) or {}
    agent = raw.get("agent", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    predecoder = raw.get("predecoder", {}) or {}

    src_ip = data.get("srcip") or predecoder.get("srcip") or raw.get("srcip") or ""
    src_port = data.get("srcport") or data.get("srcport") or raw.get("srcport") or ""
    src_user = data.get("srcuser") or data.get("user") or ""
    dst_user = data.get("dstuser") or ""
    command = data.get("command") or ""

    rule_id = str(rule.get("id", "0"))
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    description = rule.get("description", "Evento desconocido")

    ts = raw.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())
    event_id = str(raw.get("id") or f"{ts}:{rule_id}:{agent.get('id', '000')}")

    return {
        "id": event_id,
        "timestamp": ts,
        "rule_id": rule_id,
        "level": level,
        "description": description,
        "agent_id": str(agent.get("id", "000")),
        "agent_name": agent.get("name", "manager"),
        "src_ip": str(src_ip) if src_ip else "",
        "src_port": str(src_port) if src_port else "",
        "src_user": str(src_user) if src_user else "",
        "dst_user": str(dst_user) if dst_user else "",
        "command": str(command) if command else "",
        "location": raw.get("location", ""),
        "mitre_ids": mitre.get("id", []) or [],
        "mitre_tactics": mitre.get("tactic", []) or [],
        "mitre_techniques": mitre.get("technique", []) or [],
        "full_log": raw.get("full_log") or description,
        "groups": rule.get("groups", []) or [],
        "source": raw.get("_source", "unknown"),
        "raw_json": raw,
    }


class TrafficStreamWatcher:
    """
    Vigila el journal compartido y emite eventos SSE en tiempo real.
    Fuentes (local/ssh/api) corren solo en el worker líder para no duplicar polls.
    """

    def __init__(self, max_buffer: int = 400) -> None:
        self.max_buffer = max_buffer
        self.buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer)
        self._subscribers: set[asyncio.Queue] = set()
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._source_mode = settings.traffic_source.lower()
        self._is_leader = False
        self._resolved_source = "off"
        self._seen_ids: set[str] = set()
        self._seen_order: deque[str] = deque(maxlen=2000)
        self._journal_fd: Any = None
        self._journal_offset = 0
        self._leader_fd: Any = None
        self._source_task: asyncio.Task | None = None

    # ── ciclo de vida ──────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        journal = get_journal()
        # Poblar buffer desde el journal (compartido entre workers)
        for ev in journal.tail(self.max_buffer):
            self.buffer.append(ev)
            self._mark_seen(ev.get("id", ""))

        self._tasks.append(
            asyncio.create_task(self._journal_follow_loop(), name="traffic_journal_follow")
        )
        self._tasks.append(
            asyncio.create_task(self._source_leader_loop(), name="traffic_source_leader")
        )
        _log.info(
            "traffic_stream_started mode=%s journal=%s buffer=%d",
            self._source_mode, journal.path, len(self.buffer),
        )

    async def stop(self) -> None:
        self._running = False
        for t in list(self._tasks):
            t.cancel()
        for t in list(self._tasks):
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        if self._journal_fd is not None:
            try:
                self._journal_fd.close()
            except Exception:
                pass
            self._journal_fd = None
        if self._leader_fd is not None:
            try:
                import fcntl

                fcntl.flock(self._leader_fd.fileno(), fcntl.LOCK_UN)
                self._leader_fd.close()
            except Exception:
                pass
            self._leader_fd = None
        _log.info("traffic_stream_stopped")

    # ── suscriptores SSE ───────────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def broadcast(self, event: dict[str, Any]) -> None:
        """Difunde solo al proceso local (ya persistido en journal si aplica)."""
        eid = str(event.get("id", ""))
        if eid:
            self._mark_seen(eid)
        self.buffer.append(event)
        dead = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
            except Exception:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Lee del journal compartido (consistente entre workers)."""
        try:
            items = get_journal().tail(limit=limit)
            if items:
                return items
        except Exception as e:
            _log.warning("journal_tail_error err=%s", e)
        lim = min(limit, len(self.buffer))
        return list(self.buffer)[-lim:] if lim > 0 else []

    def get_source_info(self) -> dict[str, Any]:
        return {
            "mode": self._source_mode,
            "resolved": self._resolved_source,
            "is_leader": self._is_leader,
            "journal": str(get_journal().path),
            "buffer_size": len(self.buffer),
            "pid": os.getpid(),
        }

    def record_manual_event(self, raw_alert: dict[str, Any], source: str = "relay") -> None:
        """Inyecta un evento (alerts.py, simulate) → journal + broadcast local."""
        raw = dict(raw_alert)
        raw.setdefault("_source", source)
        normalized = normalize_wazuh_event(raw)
        self._ingest(normalized)

    def _ingest(self, normalized: dict[str, Any]) -> None:
        eid = str(normalized.get("id", ""))
        if eid and self._is_seen(eid):
            return
        try:
            get_journal().append(normalized)
        except Exception as e:
            _log.warning("journal_append_error err=%s", e)
        self.broadcast(normalized)

    def _mark_seen(self, eid: str) -> None:
        if not eid:
            return
        if eid in self._seen_ids:
            return
        self._seen_ids.add(eid)
        self._seen_order.append(eid)
        while len(self._seen_order) > self._seen_order.maxlen:  # type: ignore[operator]
            old = self._seen_order.popleft()
            self._seen_ids.discard(old)

    def _is_seen(self, eid: str) -> bool:
        return eid in self._seen_ids

    # ── follower del journal (todos los workers) ───────────────────────────

    async def _journal_follow_loop(self) -> None:
        journal = get_journal()
        while self._running:
            try:
                if self._journal_fd is None:
                    self._journal_fd, self._journal_offset = journal.open_for_follow()
                    # Si otro worker ya escribió, no re-broadcast del offset actual
                # Detectar rotación/truncado
                try:
                    st = journal.path.stat()
                    if st.st_size < self._journal_offset:
                        _log.info("journal_truncated reseek")
                        self._journal_offset = 0
                except FileNotFoundError:
                    await asyncio.sleep(1.0)
                    continue

                self._journal_offset, lines = await asyncio.to_thread(
                    journal.read_new_lines, self._journal_fd, self._journal_offset
                )
                for line in lines:
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    eid = str(data.get("id", ""))
                    if eid and self._is_seen(eid):
                        continue
                    # Ya viene normalizado del journal (o lo normalizamos por si acaso)
                    if "rule_id" not in data:
                        data = normalize_wazuh_event(data)
                    self.broadcast(data)
                await asyncio.sleep(0.3)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _log.warning("journal_follow_error err=%s", e)
                await asyncio.sleep(1.0)

    # ── leader election + fuentes externas ─────────────────────────────────

    async def _source_leader_loop(self) -> None:
        """Un solo worker (getpid hash / lock file) corre las fuentes externas."""
        lock_path = Path(settings.relay_lib_dir) / "traffic_source.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        while self._running:
            try:
                leader = await asyncio.to_thread(self._try_acquire_leader, lock_path)
                was = self._is_leader
                self._is_leader = leader
                if leader:
                    if not was:
                        _log.info("traffic_source_leader_acquired pid=%s", os.getpid())
                    # (Re)iniciar poll si el task murió o aún no arrancó
                    if self._source_task is None or self._source_task.done():
                        if self._source_mode != "off":
                            await self._run_sources()
                elif was:
                    _log.info("traffic_source_leader_lost pid=%s", os.getpid())
                    self._resolved_source = "follower"
                    if self._source_task and not self._source_task.done():
                        self._source_task.cancel()
                # El no-líder solo espera; el follower se mantiene por si gana el lock
                await asyncio.sleep(2.0 if self._is_leader else 1.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _log.warning("source_leader_error err=%s", e)
                await asyncio.sleep(2.0)

    def _try_acquire_leader(self, lock_path: Path) -> bool:
        """Intenta tomar un lock no bloqueante; lo mantiene mientras viva el proceso."""
        import fcntl

        if not hasattr(self, "_leader_fd") or self._leader_fd is None:
            fd = open(lock_path, "a+")
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._leader_fd = fd
                return True
            except OSError:
                fd.close()
                return False
        return True

    async def _run_sources(self) -> None:
        """Resuelve la fuente y lanza el loop de poll adecuado (una sola vez)."""
        mode = self._source_mode
        resolved = await self._resolve_source(mode)
        self._resolved_source = resolved
        if resolved == "off" or not resolved:
            _log.info("traffic_sources_disabled mode=%s", mode)
            # Cancelar loop de poll si estaba
            return

        # Evitar múltiples loops de poll en el mismo proceso
        if self._source_task is not None and not self._source_task.done():
            return

        if resolved == "local":
            self._source_task = asyncio.create_task(
                self._local_file_loop(), name="traffic_source_poll"
            )
        elif resolved == "ssh":
            self._source_task = asyncio.create_task(
                self._ssh_poll_loop(), name="traffic_source_poll"
            )
        elif resolved == "api":
            self._source_task = asyncio.create_task(
                self._api_poll_loop(), name="traffic_source_poll"
            )
        else:
            return
        self._tasks.append(self._source_task)
        _log.info("traffic_source_polling source=%s interval=%ss",
                  resolved, settings.traffic_poll_interval_sec)

    async def _resolve_source(self, mode: str) -> str:
        if mode == "off":
            return "off"
        if mode == "local":
            return "local" if Path(settings.wazuh_alerts_json_path).exists() else "off"
        if mode == "ssh":
            return "ssh"
        if mode == "api":
            return "api"
        # auto
        local_path = Path(settings.wazuh_alerts_json_path)
        if local_path.exists() and os.access(local_path, os.R_OK):
            try:
                with open(local_path, "rb") as f:
                    f.read(1)
                return "local"
            except OSError:
                pass
        host = settings.wazuh_manager_host or settings.wazuh_server_ip
        if settings.wazuh_manager_api_pass and host:
            return "api"
        if host and settings.wazuh_vm_ssh_user:
            return "ssh"
        return "off"

    # ── fuente local ───────────────────────────────────────────────────────

    async def _local_file_loop(self) -> None:
        path = Path(settings.wazuh_alerts_json_path)
        interval = max(0.3, float(settings.traffic_poll_interval_sec))
        while self._running and self._is_leader:
            if not path.exists():
                await asyncio.sleep(2.0)
                continue
            try:
                file_obj = await asyncio.to_thread(
                    open, path, mode="r", encoding="utf-8", errors="ignore"
                )
                file_obj.seek(0, os.SEEK_END)
                last_ino = os.fstat(file_obj.fileno()).st_ino
                while self._running and self._is_leader:
                    try:
                        curr = path.stat()
                        if curr.st_ino != last_ino or curr.st_size < file_obj.tell():
                            break
                    except FileNotFoundError:
                        break
                    line = await asyncio.to_thread(file_obj.readline)
                    if line:
                        s = line.strip()
                        if s.startswith("{") and s.endswith("}"):
                            try:
                                raw = json.loads(s)
                                raw["_source"] = "local"
                                self._ingest(normalize_wazuh_event(raw))
                            except json.JSONDecodeError:
                                pass
                    else:
                        await asyncio.sleep(interval)
                file_obj.close()
            except PermissionError:
                _log.warning("sin permisos en %s (grupo wazuh?)", path)
                await asyncio.sleep(5.0)
            except Exception as e:
                _log.warning("local_file_loop err=%s", e)
                await asyncio.sleep(2.0)

    # ── fuente SSH (alerts.json en la VM manager) ──────────────────────────

    def _ssh_base_cmd(self) -> list[str]:
        host = settings.wazuh_server_ip
        user = settings.wazuh_vm_ssh_user
        port = str(settings.wazuh_vm_ssh_port)
        cmd = [
            "ssh",
            "-p", port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
        ]
        if settings.wazuh_vm_ssh_key_path:
            cmd += ["-i", settings.wazuh_vm_ssh_key_path]
        cmd.append(f"{user}@{host}")
        return cmd

    async def _ssh_poll_loop(self) -> None:
        interval = max(1.0, float(settings.traffic_poll_interval_sec))
        remote_path = settings.wazuh_alerts_json_path
        # Estado: última línea ya vista (id) y cantidad de líneas leídas
        last_count = 0
        _log.info("ssh_traffic_source_start host=%s path=%s",
                  settings.wazuh_server_ip, remote_path)
        while self._running and self._is_leader:
            try:
                count_cmd = self._ssh_base_cmd() + [
                    f"wc -l < {remote_path} 2>/dev/null || echo 0"
                ]
                proc = await asyncio.create_subprocess_exec(
                    *count_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
                if proc.returncode != 0:
                    _log.warning("ssh_wc_failed rc=%s err=%s",
                                 proc.returncode, (err or b"").decode()[:200])
                    await asyncio.sleep(interval * 2)
                    continue
                try:
                    count = int((out or b"").decode().strip() or "0")
                except ValueError:
                    count = 0

                if count > last_count:
                    n_new = min(count - last_count, 100)
                    start = count - n_new + 1
                    tail_cmd = self._ssh_base_cmd() + [
                        f"tail -n +{start} {remote_path} 2>/dev/null"
                    ]
                    proc2 = await asyncio.create_subprocess_exec(
                        *tail_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    out2, err2 = await asyncio.wait_for(proc2.communicate(), timeout=20)
                    if proc2.returncode == 0 and out2:
                        for line in out2.decode("utf-8", errors="ignore").splitlines():
                            s = line.strip()
                            if not (s.startswith("{") and s.endswith("}")):
                                continue
                            try:
                                raw = json.loads(s)
                            except json.JSONDecodeError:
                                continue
                            raw["_source"] = "ssh"
                            self._ingest(normalize_wazuh_event(raw))
                    last_count = count
                elif count < last_count:
                    # rotación remota
                    last_count = count
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _log.warning("ssh_poll_error err=%s", e)
                await asyncio.sleep(interval * 2)

    # ── fuente API del manager ─────────────────────────────────────────────

    async def _api_poll_loop(self) -> None:
        """Poll de alertas recientes vía Wazuh API (si expone /alerts)."""
        from ..infrastructure.notifier import _get_token

        interval = max(1.0, float(settings.traffic_poll_interval_sec))
        host = settings.wazuh_manager_host or settings.wazuh_server_ip
        base = f"https://{host}:{settings.wazuh_manager_api_port}"
        verify = settings.wazuh_manager_api_verify_tls
        seen_ts_rule: deque[str] = deque(maxlen=2000)
        _log.info("api_traffic_source_start base=%s", base)

        while self._running and self._is_leader:
            token = None
            try:
                async with httpx.AsyncClient(timeout=10, verify=verify) as client:
                    token = await _get_token(client)
                    if not token:
                        await asyncio.sleep(interval * 4)
                        continue
                    headers = {"Authorization": f"Bearer {token}"}
                    # Intentar varios endpoints comunes de alertas según versión
                    for url in (
                        f"{base}/alerts?limit=50&sort=-timestamp",
                        f"{base}/alerts",
                    ):
                        r = await client.get(url, headers=headers)
                        if not r.is_success:
                            continue
                        payload = r.json()
                        items = (
                            payload.get("data", {}).get("affected_items")
                            or payload.get("alerts")
                            or []
                        )
                        for raw in items:
                            if not isinstance(raw, dict):
                                continue
                            ts = str(raw.get("timestamp", ""))
                            rid = str((raw.get("rule") or {}).get("id", ""))
                            aid = str((raw.get("agent") or {}).get("id", "000"))
                            key = f"{ts}:{rid}:{aid}"
                            if key in seen_ts_rule:
                                continue
                            seen_ts_rule.append(key)
                            raw["_source"] = "api"
                            self._ingest(normalize_wazuh_event(raw))
                        break
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _log.warning("api_poll_error err=%s", e)
                await asyncio.sleep(interval * 3)


# Instancia singleton por worker
traffic_watcher = TrafficStreamWatcher()
