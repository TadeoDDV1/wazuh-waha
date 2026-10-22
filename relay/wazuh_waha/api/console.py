"""Consola web interactiva (PTY local y SSH).

Seguridad:
  - Requiere sesión BFF con scope "full".
  - Valida Origin en el handshake WebSocket.
  - Solo destinos permitidos por CONSOLE_TARGETS / CONSOLE_AGENT_TARGETS.
  - Shell local corre como el usuario del servicio (nunca root).
  - SSH usa las mismas claves/known_hosts que el resto del relay.
  - Límite de sesiones, timeout de inactividad y timeout absoluto.
  - Auditoría de apertura/cierre y transcripción opcional.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import struct
import termios
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from .deps import verify_write
from ..common.audit import get_audit_log
from ..common.logging import log
from ..common.session import SCOPE_FULL, verify_session
from ..config import settings
from ..infrastructure.ssh_pool import ssh_pool

router = APIRouter(prefix="/api/v1/console", tags=["console"])

_sessions = 0
_sessions_lock = asyncio.Lock()


def _targets() -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    allowed = set(settings.console_targets_list)
    if settings.console_allow_local_shell and "local" in allowed:
        targets.append({"id": "local", "label": "Shell local (relay)", "type": "local"})
    if "manager" in allowed and ssh_pool.configured:
        targets.append({
            "id": "manager",
            "label": f"SSH Wazuh Manager ({settings.wazuh_vm_ssh_user}@{ssh_pool.host})",
            "type": "ssh",
        })
    for aid in settings.console_agent_targets_map:
        if f"agent:{aid}" in allowed or "agents" in allowed:
            dest = settings.console_agent_targets_map[aid]
            targets.append({
                "id": f"agent:{aid}",
                "label": f"SSH Agente {aid} ({dest})",
                "type": "ssh",
            })
    return targets


@router.get("/targets")
async def console_targets(_: None = Depends(verify_write)):
    return {
        "ok": True,
        "enabled": bool(settings.console_enabled),
        "targets": _targets() if settings.console_enabled else [],
        "max_sessions": settings.console_max_sessions,
        "idle_timeout_sec": settings.console_idle_timeout_sec,
    }


def _origin_allowed(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return True
    parsed = urlparse(origin)
    host = parsed.hostname or ""
    if not host:
        return False
    allowed_hosts = set()
    for item in settings.cors_origins_list:
        p = urlparse(item)
        if p.hostname:
            allowed_hosts.add(p.hostname)
    req_host = (websocket.url.hostname or "").strip()
    return host in allowed_hosts or host == req_host


def _ssh_command(dest: str) -> list[str]:
    cmd = ssh_pool._base_cmd()  # type: ignore[attr-defined]
    # _base_cmd termina con user@host; lo reemplazamos y forzamos PTY.
    cmd = cmd[:-1]
    cmd += ["-tt", dest]
    return cmd


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


async def _audit(action: str, target: str, sid: str, ip: str, **extra) -> None:
    try:
        get_audit_log().record(
            method=f"WS:{action}",
            path="/api/v1/console/ws",
            status=200,
            ip=ip,
            sid=sid,
            scope="full",
            detail=json.dumps({"target": target, **extra}, ensure_ascii=False)[:200],
        )
    except Exception:
        pass


@router.websocket("/ws")
async def console_ws(websocket: WebSocket) -> None:
    global _sessions

    if not settings.console_enabled:
        await websocket.close(code=4403)
        return

    token = websocket.cookies.get("ww_session")
    payload = verify_session(token)
    if payload is None or payload.get("scope") != SCOPE_FULL:
        await websocket.close(code=4401)
        return
    if not _origin_allowed(websocket):
        await websocket.close(code=4403)
        return

    target = (websocket.query_params.get("target") or "").strip()
    valid = {t["id"]: t for t in _targets()}
    if target not in valid:
        await websocket.close(code=4404)
        return

    async with _sessions_lock:
        if _sessions >= max(1, settings.console_max_sessions):
            await websocket.close(code=4429)
            return
        _sessions += 1

    await websocket.accept()
    sid = f"console-{uuid.uuid4().hex[:12]}"
    client_ip = websocket.client.host if websocket.client else "?"
    started = time.time()
    transcript_path: Path | None = None
    if settings.console_record_transcript:
        try:
            log_dir = Path(settings.relay_log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            transcript_path = log_dir / f"{sid}.log"
        except Exception:
            transcript_path = None

    t = valid[target]
    if t["type"] == "local":
        shell = os.environ.get("SHELL") or "/bin/bash"
        cmd = [shell, "-l"]
        cwd = os.path.expanduser("~")
    else:
        if target == "manager":
            dest = f"{settings.wazuh_vm_ssh_user}@{ssh_pool.host}"
        else:
            dest = settings.console_agent_targets_map.get(target.split(":", 1)[1], "")
            if not dest:
                await websocket.close(code=4404)
                return
        cmd = _ssh_command(dest)
        cwd = None

    master, slave = pty.openpty()
    _set_winsize(master, 30, 120)
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=cwd,
            env=env,
            preexec_fn=os.setsid,
        )
    except Exception as exc:
        os.close(master)
        os.close(slave)
        async with _sessions_lock:
            _sessions -= 1
        log.warning("console_spawn_failed target=%s err=%s", target, exc)
        await websocket.close(code=1011)
        return
    os.close(slave)
    await _audit("open", target, payload.get("sid", "-"), client_ip, session=sid)

    async def reader() -> None:
        while True:
            try:
                data = await asyncio.to_thread(os.read, master, 4096)
            except OSError:
                break
            if not data:
                break
            try:
                await websocket.send_text(data.decode("utf-8", errors="replace"))
            except Exception:
                break
            if transcript_path is not None:
                try:
                    with open(transcript_path, "ab") as fh:
                        fh.write(data)
                except Exception:
                    pass

    async def writer() -> None:
        while True:
            try:
                msg = await asyncio.wait_for(
                    websocket.receive(), timeout=max(30, settings.console_idle_timeout_sec)
                )
            except asyncio.TimeoutError:
                try:
                    await websocket.close(code=4408)
                except Exception:
                    pass
                break
            if msg.get("type") == "websocket.disconnect":
                break
            data = msg.get("text")
            if data is None and msg.get("bytes") is not None:
                raw = msg["bytes"]
            else:
                raw = (data or "").encode("utf-8", errors="replace")
                text = (data or "").strip()
                if text.startswith("{"):
                    try:
                        parsed = json.loads(text)
                        if parsed.get("type") == "resize":
                            _set_winsize(
                                master,
                                int(parsed.get("rows", 30)),
                                int(parsed.get("cols", 120)),
                            )
                            continue
                        if parsed.get("type") == "input":
                            raw = str(parsed.get("data", "")).encode("utf-8", errors="replace")
                    except Exception:
                        pass
            try:
                os.write(master, raw)
            except OSError:
                break

    read_task = asyncio.create_task(reader())
    write_task = asyncio.create_task(writer())
    try:
        await asyncio.wait_for(
            asyncio.wait(
                {read_task, write_task}, return_when=asyncio.FIRST_COMPLETED
            ),
            timeout=max(60, settings.console_absolute_timeout_sec),
        )
    except asyncio.TimeoutError:
        pass
    finally:
        for task in (read_task, write_task):
            task.cancel()
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            os.close(master)
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
        async with _sessions_lock:
            _sessions -= 1
        await _audit(
            "close", target, payload.get("sid", "-"), client_ip,
            session=sid, duration_sec=round(time.time() - started, 1),
        )
        log.info("console_session_closed target=%s session=%s duration=%.1fs",
                 target, sid, time.time() - started)
