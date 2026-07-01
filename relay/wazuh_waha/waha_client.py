"""
Cliente async para WAHA (WhatsApp HTTP API).
Con logging detallado de cada paso del envio + counter de fallos +
auto-recovery cuando la sesion esta STOPPED.
"""
import asyncio
import logging
import time
from collections import deque
from threading import Lock

import httpx

from . import notifier
from .config import settings

log = logging.getLogger("wazuh-waha.waha")

# --- Counter de fallos para detectar sesion WAHA rota ---
_fail_window: deque[float] = deque(maxlen=20)
_fail_lock = Lock()
FAIL_THRESHOLD = 5
FAIL_WINDOW_SEC = 60

# --- Auto-recovery: anti-loop entre requests concurrentes ---
_recovery_lock = asyncio.Lock()
_recovery_in_progress = False
_recovery_last_attempt: float = 0.0


class WAHAError(Exception):
    pass


def _record_failure() -> int:
    """Registra un fallo y devuelve la cantidad en la ventana movil."""
    with _fail_lock:
        now = time.time()
        _fail_window.append(now)
        while _fail_window and now - _fail_window[0] > FAIL_WINDOW_SEC:
            _fail_window.popleft()
        return len(_fail_window)


def _reset_failures() -> None:
    with _fail_lock:
        _fail_window.clear()


def _check_failure_threshold(count: int) -> None:
    """Si hay muchos fallos seguidos, log CRITICAL con sugerencia."""
    if count >= FAIL_THRESHOLD:
        log.critical(
            "waha_send_alerting_failures count=%d window=%ds "
            "posible_causa=sesion_caida|api_key_invalida|waha_offline "
            "accion=sugerir_revisar_sesion_waha_y_relay_health",
            count, FAIL_WINDOW_SEC,
        )


def _is_session_stopped_error(body_text: str) -> bool:
    """Detecta si un 422 de WAHA indica sesion STOPPED (caso recuperable)."""
    if not body_text:
        return False
    low = body_text.lower()
    return "stopped" in low and "expected" in low


async def _stop_session(client: httpx.AsyncClient) -> None:
    """POST /sessions/{name}/stop. Best-effort."""
    try:
        url = f"{settings.waha_host}/api/sessions/{settings.waha_session}/stop"
        r = await client.post(url, headers={"X-Api-Key": settings.waha_api_key})
        log.info("waha_recover_step step=stop status=%d body=%r",
                 r.status_code, r.text[:200])
    except Exception as e:
        log.warning("waha_recover_step step=stop err=%s", e)


async def _start_session(client: httpx.AsyncClient) -> None:
    """POST /sessions/{name}/start. Best-effort."""
    try:
        url = f"{settings.waha_host}/api/sessions/{settings.waha_session}/start"
        r = await client.post(url, headers={"X-Api-Key": settings.waha_api_key})
        log.info("waha_recover_step step=start status=%d body=%r",
                 r.status_code, r.text[:200])
    except Exception as e:
        log.warning("waha_recover_step step=start err=%s", e)


async def _get_session_status(client: httpx.AsyncClient) -> str:
    """Devuelve el campo status de la sesion o 'unknown' si falla."""
    try:
        url = f"{settings.waha_host}/api/sessions/{settings.waha_session}"
        r = await client.get(url, headers={"X-Api-Key": settings.waha_api_key})
        if r.is_success:
            return r.json().get("status", "unknown")
    except Exception as e:
        log.warning("waha_recover_step step=status err=%s", e)
    return "unknown"


async def _auto_recover_session() -> None:
    """
    Intenta recuperar la sesion WAHA en background.
    Secuencia: stop -> wait 5s -> start -> poll hasta WORKING (max wait).
    Notifica el resultado por Wazuh API + email.
    Anti-loop: cooldown global y lock para evitar N recoveries simultaneos.
    """
    global _recovery_in_progress, _recovery_last_attempt

    async with _recovery_lock:
        if _recovery_in_progress:
            log.debug("waha_recover_skip already_in_progress")
            return
        now = time.time()
        if now - _recovery_last_attempt < settings.waha_recovery_cooldown_sec:
            log.warning(
                "waha_recover_skip cooldown_active since_last=%.0fs cooldown=%ds",
                now - _recovery_last_attempt, settings.waha_recovery_cooldown_sec,
            )
            return
        _recovery_in_progress = True
        _recovery_last_attempt = now

    log.critical(
        "waha_recover_start session=%s cooldown=%ds max_wait=%ds",
        settings.waha_session,
        settings.waha_recovery_cooldown_sec,
        settings.waha_recovery_max_wait_sec,
    )
    await notifier.notify_health(
        f"WAHA session {settings.waha_session} STOPPED - auto-recovery triggered",
        level=15,
        session=settings.waha_session,
        action="auto_recovery_start",
    )

    recovered = False
    final_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            await _stop_session(client)
            await asyncio.sleep(5)
            await _start_session(client)

            max_wait = settings.waha_recovery_max_wait_sec
            poll_interval = 5
            elapsed = 0
            while elapsed <= max_wait:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                final_status = await _get_session_status(client)
                log.info("waha_recover_poll elapsed=%ds status=%s", elapsed, final_status)
                if final_status == "WORKING":
                    recovered = True
                    break
                if final_status in ("FAILED", "STOPPED"):
                    break

        if recovered:
            log.info("waha_recover_ok elapsed=%ds status=%s", elapsed, final_status)
            await notifier.notify_health(
                f"WAHA session {settings.waha_session} recovered successfully",
                level=10,
                session=settings.waha_session,
                action="auto_recovered",
                elapsed_sec=elapsed,
                final_status=final_status,
            )
            _reset_failures()
        else:
            log.critical(
                "waha_recover_failed final_status=%s elapsed=%ds", final_status, elapsed
            )
            await notifier.notify_health(
                f"WAHA session {settings.waha_session} recovery FAILED "
                f"(status={final_status})",
                level=15,
                session=settings.waha_session,
                action="auto_recovery_failed",
                elapsed_sec=elapsed,
                final_status=final_status,
            )
    except Exception as e:
        log.exception("waha_recover_exception err=%s", e)
        await notifier.notify_health(
            f"WAHA session {settings.waha_session} recovery raised exception: {e}",
            level=15,
            session=settings.waha_session,
            action="auto_recovery_exception",
        )
    finally:
        _recovery_in_progress = False


async def send_text(text: str, chat_id: str | None = None, session: str | None = None) -> dict:
    """Envia mensaje de texto. Devuelve respuesta cruda de WAHA."""
    final_chat = chat_id or settings.admin_chat_id
    final_session = session or settings.waha_session
    payload = {
        "session": final_session,
        "chatId": final_chat,
        "text": text,
    }
    headers = {
        "X-Api-Key": settings.waha_api_key,
        "Content-Type": "application/json",
    }

    log.info(
        "waha_send_start chat=%s session=%s msg_len=%d text_preview=%r",
        final_chat, final_session, len(text), text[:80],
    )

    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{settings.waha_host}/api/sendText",
                json=payload,
                headers=headers,
            )
        elapsed_ms = int((time.time() - t0) * 1000)

        if r.is_success:
            log.info(
                "waha_request_done status=%d elapsed_ms=%d endpoint=%s",
                r.status_code, elapsed_ms, "/api/sendText",
            )
            try:
                body = r.json()
            except Exception:
                body = {"_raw": r.text[:300]}
            _reset_failures()
            return body
        else:
            body_txt = r.text[:500] if r.text else ""
            fails = _record_failure()
            log.error(
                "waha_request_failed status=%d elapsed_ms=%d body=%r failures_in_window=%d",
                r.status_code, elapsed_ms, body_txt, fails,
            )
            _check_failure_threshold(fails)

            # Branch especifico: sesion STOPPED -> auto-recovery en background.
            if r.status_code == 422 and _is_session_stopped_error(body_txt):
                log.critical(
                    "waha_session_stopped_detected session=%s triggering_auto_recovery",
                    final_session,
                )
                asyncio.create_task(_auto_recover_session())

            raise WAHAError(f"WAHA HTTP {r.status_code}: {body_txt}")
    except httpx.TimeoutException as e:
        fails = _record_failure()
        elapsed_ms = int((time.time() - t0) * 1000)
        log.error(
            "waha_request_timeout elapsed_ms=%d err=%s failures_in_window=%d",
            elapsed_ms, e, fails,
        )
        _check_failure_threshold(fails)
        raise WAHAError(f"WAHA timeout after {elapsed_ms}ms: {e}") from e
    except httpx.HTTPStatusError as e:
        body = ""
        try:
            body = e.response.text[:300]
        except Exception:
            pass
        fails = _record_failure()
        log.error(
            "waha_request_http_error status=%d body=%r failures_in_window=%d",
            e.response.status_code, body, fails,
        )
        _check_failure_threshold(fails)
        raise WAHAError(f"WAHA HTTP {e.response.status_code}: {body}") from e
    except Exception as e:
        fails = _record_failure()
        elapsed_ms = int((time.time() - t0) * 1000)
        log.exception(
            "waha_request_exception elapsed_ms=%d err=%s failures_in_window=%d",
            elapsed_ms, e, fails,
        )
        _check_failure_threshold(fails)
        raise WAHAError(f"WAHA request failed: {e}") from e