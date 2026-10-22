"""Ejecución SSH reutilizable contra el Wazuh Manager.

Usa el binario ssh del sistema con ControlMaster/ControlPersist para evitar
abrir una conexión nueva por cada poll (ss, cat, python3). No requiere
dependencias Python adicionales y respeta BatchMode: si no hay clave, falla
rápido en lugar de quedar colgado pidiendo contraseña.
"""

from __future__ import annotations

import asyncio
import base64
import json
import shlex
from typing import Any

from ..common.logging import log
from ..config import settings


class SSHError(Exception):
    pass


class SSHPool:
    def __init__(self) -> None:
        self._sem = asyncio.Semaphore(8)

    @property
    def configured(self) -> bool:
        return bool(
            (settings.wazuh_manager_host or settings.wazuh_server_ip)
            and settings.wazuh_vm_ssh_user
        )

    @property
    def host(self) -> str:
        return settings.wazuh_manager_host or settings.wazuh_server_ip

    def _base_cmd(self) -> list[str]:
        strict = str(settings.wazuh_vm_ssh_strict_host_key or "accept-new").lower()
        if strict not in ("yes", "accept-new", "no"):
            strict = "accept-new"
        control_path = f"/tmp/ssh-wazuh-%r@%h:%p"
        cmd = [
            "ssh",
            "-p",
            str(settings.wazuh_vm_ssh_port),
            "-o",
            f"StrictHostKeyChecking={strict}",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={control_path}",
            "-o",
            "ControlPersist=600s",
        ]
        if settings.wazuh_vm_ssh_key_path:
            cmd += ["-i", settings.wazuh_vm_ssh_key_path, "-o", "IdentitiesOnly=yes"]
        cmd.append(f"{settings.wazuh_vm_ssh_user}@{self.host}")
        return cmd

    async def run(
        self,
        command: str,
        *,
        timeout: float = 12.0,
        check: bool = False,
    ) -> tuple[int, str, str]:
        """Ejecuta un comando remoto y devuelve (returncode, stdout, stderr)."""
        if not self.configured:
            raise SSHError("SSH al manager no configurado (WAZUH_VM_SSH_USER/host)")
        async with self._sem:
            proc = await asyncio.create_subprocess_exec(
                *self._base_cmd(),
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise SSHError(f"SSH timeout ejecutando: {command[:120]}")
            out = out_b.decode("utf-8", errors="ignore")
            err = err_b.decode("utf-8", errors="ignore")
            if check and proc.returncode != 0:
                raise SSHError(
                    f"SSH rc={proc.returncode} cmd={command[:120]} err={err[:300]}"
                )
            return proc.returncode, out, err

    async def read_text(self, path: str, *, timeout: float = 10.0) -> str:
        rc, out, err = await self.run(f"cat -- {shlex.quote(path)}", timeout=timeout)
        if rc != 0:
            raise SSHError(f"No se pudo leer {path}: {err[:200]}")
        return out

    async def read_json(self, path: str, *, timeout: float = 10.0) -> Any:
        raw = await self.read_text(path, timeout=timeout)
        return json.loads(raw)

    async def python(self, script: str, *, timeout: float = 15.0) -> str:
        """Ejecuta un script Python remoto y devuelve stdout."""
        rc, out, err = await self.run(
            f"python3 -c {shlex.quote(script)}", timeout=timeout
        )
        if rc != 0:
            raise SSHError(f"python3 remoto falló: {err[:300]}")
        return out

    async def read_sqlite_json(
        self, db_path: str, query: str, *, timeout: float = 15.0
    ) -> list[dict[str, Any]]:
        script = (
            "import sqlite3,json,sys\n"
            f"c=sqlite3.connect('file:{db_path}?mode=ro',uri=True)\n"
            "c.row_factory=sqlite3.Row\n"
            f"rows=[dict(r) for r in c.execute({query!r})]\n"
            "print(json.dumps(rows,default=str))\n"
        )
        out = await self.python(script, timeout=timeout)
        return json.loads(out or "[]")

    async def write_bytes_b64(
        self, path: str, data: bytes, *, timeout: float = 15.0
    ) -> None:
        """Escritura atómica vía base64. Requiere permiso de escritura del usuario."""
        b64 = base64.b64encode(data).decode("ascii")
        target = shlex.quote(path)
        script = "import base64,sys; open(sys.argv[1], 'wb').write(base64.b64decode(sys.stdin.read()))"
        command = f"python3 -c {shlex.quote(script)} {target}"
        proc = await asyncio.create_subprocess_exec(
            *self._base_cmd(),
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(b64.encode("ascii")), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise SSHError("SSH timeout escribiendo archivo remoto")
        if proc.returncode != 0:
            raise SSHError(err_b.decode("utf-8", "ignore")[:300])

    async def write_bytes_b64_sudo(
        self, path: str, data: bytes, *, timeout: float = 15.0
    ) -> None:
        """Escritura atómica con `sudo -n tee` (requiere sudo sin contraseña)."""
        b64 = base64.b64encode(data).decode("ascii")
        target = shlex.quote(path)
        script = "import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))"
        command = f"python3 -c {shlex.quote(script)} | sudo -n tee {target} >/dev/null"
        proc = await asyncio.create_subprocess_exec(
            *self._base_cmd(),
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _out_b, err_b = await asyncio.wait_for(
                proc.communicate(b64.encode("ascii")), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise SSHError("SSH timeout escribiendo archivo remoto con sudo")
        if proc.returncode != 0:
            raise SSHError(err_b.decode("utf-8", "ignore")[:300])

    async def sudo_available(self) -> bool:
        try:
            rc, _, _ = await self.run("sudo -n true", timeout=5)
            return rc == 0
        except Exception:
            return False

    async def close(self) -> None:
        # Cierra el master si existe; best-effort.
        try:
            await self.run("true", timeout=3)
        except Exception:
            pass


ssh_pool = SSHPool()
