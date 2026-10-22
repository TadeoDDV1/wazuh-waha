"""Bus de conexiones de red reales.

Fuentes:
  - `ss -tunap` en el Wazuh Manager vía SSH (en vivo, sin datos sintéticos).
  - syscollector (`/syscollector/{agent}/ports`) para agentes remotos.

No captura payload ni inventa latencias/paquetes. Si una fuente no está
disponible, lo reporta en `stats` y deja de emitir ese origen.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from typing import Any

from ..config import settings
from ..infrastructure.ssh_pool import ssh_pool
from ..infrastructure.wazuh_api import wazuh_api, WazuhAPIError
from .dns_cache import resolve_many
from .logging import log

_PROC_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
_KNOWN_PORTS = {
    22: "ssh",
    53: "dns",
    80: "http",
    123: "ntp",
    443: "https",
    1514: "wazuh-remoted",
    1515: "wazuh-authd",
    3001: "waha",
    3306: "mysql",
    5432: "postgres",
    55000: "wazuh-api",
    8001: "dashboard",
    8765: "relay",
}



_KNOWN_NETS: list[tuple[str, str]] = [
    ("149.154.", "telegram.org"),
    ("91.108.", "telegram.org"),
    ("8.8.8.8", "dns.google"),
    ("8.8.4.4", "dns.google"),
    ("1.1.1.1", "one.one.one.one"),
    ("1.0.0.1", "one.one.one.one"),
    ("142.250.", "google.com"),
    ("142.251.", "google.com"),
    ("172.217.", "google.com"),
    ("192.178.", "google.com"),
    ("104.16.", "cloudflare.com"),
    ("104.18.", "cloudflare.com"),
    ("140.82.", "github.com"),
    ("185.199.", "github.com"),
    ("157.240.", "facebook.com"),
    ("31.13.", "facebook.com"),
    ("20.", "azure.microsoft.com"),
    ("52.", "azure.microsoft.com"),
]


def _fallback_domain(ip: str) -> str:
    for prefix, domain in _KNOWN_NETS:
        if ip.startswith(prefix):
            return domain
    return ""


def _parse_addr(value: str) -> tuple[str, int]:
    value = (value or "").strip()
    if not value or value == "-":
        return "", 0
    if value.startswith("["):
        end = value.rfind("]")
        if end != -1:
            addr = value[1:end]
            rest = value[end + 1 :]
            port = rest[1:] if rest.startswith(":") else "0"
            return addr.replace("::ffff:", "").split("%")[0], int(port) if port.isdigit() else 0
    if ":" in value:
        addr, port = value.rsplit(":", 1)
        return addr.replace("::ffff:", "").strip("*").split("%")[0], int(port) if port.isdigit() else 0
    return value, 0


def _direction(state: str, local_port: int, remote_port: int) -> str:
    st = (state or "").lower()
    if "listen" in st or remote_port == 0:
        return "listen"
    if local_port and remote_port:
        if local_port < 32768 <= remote_port:
            return "inbound"
        if remote_port < 32768 <= local_port:
            return "outbound"
    return "unknown"


def _parse_ss(output: str, agent_id: str, agent_name: str, agent_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto, state, _recv, _send, local, peer = parts[:6]
        proc_field = parts[6] if len(parts) > 6 else ""
        proc_name = ""
        pid = None
        m = _PROC_RE.search(proc_field)
        if m:
            proc_name, pid_s = m.group(1), m.group(2)
            pid = int(pid_s) if pid_s.isdigit() else None
        local_ip, local_port = _parse_addr(local)
        remote_ip, remote_port = _parse_addr(peer)
        if local_ip in ("*", "::", "0.0.0.0"):
            display_local = local_ip
        else:
            display_local = local_ip
        rows.append({
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "protocol": (proto or "tcp").upper(),
            "state": (state or "UNKNOWN").upper(),
            "local_ip": display_local,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "process": proc_name or _KNOWN_PORTS.get(local_port, _KNOWN_PORTS.get(remote_port, "")),
            "pid": pid,
            "direction": _direction(state, local_port, remote_port),
            "source": "ss",
        })
    return rows


def _normalize_sys_port(p: dict[str, Any], agent_id: str, agent_name: str, agent_ip: str) -> dict[str, Any]:
    local = p.get("local") if isinstance(p.get("local"), dict) else {}
    remote = p.get("remote") if isinstance(p.get("remote"), dict) else {}
    local_ip = str(local.get("ip") or p.get("local_ip") or "").replace("::ffff:", "")
    remote_ip = str(remote.get("ip") or p.get("remote_ip") or "").replace("::ffff:", "")
    local_port = int(local.get("port") or p.get("local_port") or 0)
    remote_port = int(remote.get("port") or p.get("remote_port") or 0)
    state = str(p.get("state") or "LISTEN").upper()
    return {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "protocol": str(p.get("protocol") or "tcp").upper(),
        "state": state,
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "process": str(p.get("process") or p.get("program_name") or "") or _KNOWN_PORTS.get(local_port, ""),
        "pid": p.get("pid"),
        "direction": _direction(state, local_port, remote_port),
        "source": "syscollector",
    }


class NetworkBus:
    def __init__(self) -> None:
        self.connections: list[dict[str, Any]] = []
        self.events: deque[dict[str, Any]] = deque(maxlen=2000)
        self._subs: set[asyncio.Queue] = set()
        self._seen: dict[str, float] = {}
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._last_emit: dict[str, float] = {}
        self._agent_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])
        self._sysports_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])
        self.stats: dict[str, Any] = {
            "manager_reachable": False,
            "last_poll": 0.0,
            "last_error": "",
            "sources": [],
            "agents_total": 0,
            "connections": 0,
        }

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._tasks.append(asyncio.create_task(self._poll_loop(), name="network_bus_poll"))
        self._tasks.append(asyncio.create_task(self._agent_poll_loop(), name="network_bus_agents"))
        log.info("network_bus_started interval=%.1fs", settings.network_poll_interval_sec)

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        log.info("network_bus_stopped")

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=300)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def _broadcast(self, event: dict[str, Any]) -> None:
        dead = []
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subs.discard(q)

    def snapshot(self) -> dict[str, Any]:
        return {
            "connections": list(self.connections),
            "stats": dict(self.stats),
            "timestamp": time.time(),
        }

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        items = list(self.events)
        return items[-limit:] if limit > 0 else items

    async def _agents(self) -> list[dict[str, Any]]:
        now = time.time()
        ts, cached = self._agent_cache
        if now - ts < 30 and cached:
            return cached
        if not wazuh_api.configured:
            return cached or []
        try:
            agents = await wazuh_api.affected_items("/agents?limit=500")
            self._agent_cache = (now, agents)
            return agents
        except Exception as exc:
            log.debug("network_bus_agents_error err=%s", exc)
            return cached or []

    async def _manager_connections(self) -> list[dict[str, Any]]:
        agents = await self._agents()
        manager = next((a for a in agents if str(a.get("id")) == "000"), None) or {}
        name = manager.get("name") or "wazuh-manager"
        ip = manager.get("ip") or settings.wazuh_server_ip or "127.0.0.1"
        rc, out, err = await ssh_pool.run("ss -tunap", timeout=8)
        if rc != 0:
            raise RuntimeError(err[:200] or f"ss rc={rc}")
        self.stats["manager_reachable"] = True
        return _parse_ss(out, "000", name, ip)

    async def _agent_sysports(self, agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = time.time()
        ts, cached = self._sysports_cache
        if now - ts < 12 and cached:
            return cached
        if not wazuh_api.configured:
            return cached or []
        rows: list[dict[str, Any]] = []
        for ag in agents:
            aid = str(ag.get("id", ""))
            if not aid or aid == "000":
                continue
            name = ag.get("name", f"agente-{aid}")
            ip = ag.get("ip", "")
            try:
                data = await wazuh_api.affected_items(
                    f"/syscollector/{aid}/ports?limit=500", timeout=10
                )
            except Exception as exc:
                log.debug("network_bus_sysports_error aid=%s err=%s", aid, exc)
                continue
            for p in data:
                rows.append(_normalize_sys_port(p, aid, name, ip))
        self._sysports_cache = (now, rows)
        return rows

    async def _collect(self) -> list[dict[str, Any]]:
        agents = await self._agents()
        self.stats["agents_total"] = len(agents)
        rows: list[dict[str, Any]] = []
        sources: list[str] = []
        try:
            rows.extend(await self._manager_connections())
            sources.append("manager:ss")
        except Exception as exc:
            self.stats["manager_reachable"] = False
            self.stats["last_error"] = str(exc)[:200]
            log.debug("network_bus_manager_error err=%s", exc)
        try:
            sys_rows = await self._agent_sysports(agents)
            rows.extend(sys_rows)
            if sys_rows:
                sources.append("agents:syscollector")
        except Exception as exc:
            self.stats["last_error"] = str(exc)[:200]
        self.stats["sources"] = sources
        return rows

    async def _poll_once(self) -> None:
        rows = await self._collect()
        if not rows:
            self.stats["connections"] = 0
            self.stats["last_poll"] = time.time()
            return

        # Resolver DNS de los destinos remotos reales.
        remote_ips = {
            r["remote_ip"]
            for r in rows
            if r.get("remote_ip") and r["remote_ip"] not in ("0.0.0.0", "::", "*")
        }
        try:
            dns = await resolve_many(remote_ips)
        except Exception:
            dns = {}

        for r in rows:
            ip = r.get("remote_ip") or ""
            r["remote_hostname"] = dns.get(ip, "")
            r["domain"] = (r["remote_hostname"] or _fallback_domain(ip) or ip) if ip not in ("0.0.0.0", "::", "*", "") else ""
            r["ts"] = time.time()
            r["id"] = (
                f"{r['agent_id']}:{r['protocol']}:{r['local_ip']}:{r['local_port']}:"
                f"{r['remote_ip']}:{r['remote_port']}:{r['state']}"
            )
            r["src_ip"] = r["local_ip"]
            r["src_port"] = str(r["local_port"])
            r["dst_ip"] = r["remote_ip"]
            r["dst_port"] = str(r["remote_port"])
            r["description"] = (
                f"{r['direction'].upper()} {r['protocol']} "
                f"{r['local_ip']}:{r['local_port']} -> {r['remote_ip']}:{r['remote_port']} "
                f"[{r['process'] or 'sin proceso'}]"
            )

        # Emitir solo conexiones nuevas o cuyo estado cambió en la ventana.
        now = time.time()
        cutoff = now - 120
        for r in rows:
            key = r["id"]
            last = self._last_emit.get(key, 0.0)
            # Reemitir conexiones establecidas cada 30s para mantener la UI viva.
            interval = 30.0 if "ESTAB" in r["state"] or "LISTEN" in r["state"] else 120.0
            if now - last >= interval:
                self._last_emit[key] = now
                self.events.append(r)
                self._broadcast({"type": "connection", "data": r})

        # Limpiar claves viejas.
        for key, ts in list(self._last_emit.items()):
            if ts < cutoff:
                self._last_emit.pop(key, None)

        rows.sort(key=lambda r: (
            0 if r.get("direction") in ("inbound", "outbound") else 1,
            0 if "ESTAB" in str(r.get("state", "")).upper() else 1,
            str(r.get("agent_id", "")),
        ))
        self.connections = rows
        self.stats["connections"] = len(rows)
        self.stats["last_poll"] = now

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("network_bus_poll_error err=%s", exc)
            await asyncio.sleep(max(1.0, float(settings.network_poll_interval_sec)))

    async def _agent_poll_loop(self) -> None:
        # Refresca syscollector con más calma para no saturar la API.
        while self._running:
            try:
                agents = await self._agents()
                await self._agent_sysports(agents)
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(20.0)


network_bus = NetworkBus()
