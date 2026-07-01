"""
Cliente async para WAHA (WhatsApp HTTP API).
Con logging detallado de cada paso del envio + counter de fallos.
"""
import logging
import time
from collections import deque
from threading import Lock

import httpx

from .config import settings

log = logging.getLogger("wazuh-relay.waha")

# --- Counter de fallos para detectar sesion WAHA rota ---
_fail_window: deque[float] = deque(maxlen=20)
_fail_lock = Lock()
FAIL_THRESHOLD = 5
FAIL_WINDOW_SEC = 60


class WAHAError(Exception):
    pass


def _record_failure() -> int:
    """Registra un fallo y devuelve la cantidad en la ventana movil."""
    with _fail_lock:
        now = time.time()
        _fail_window.append(now)
        # limpia los que estan fuera de ventana
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

        # Logueamos SIEMPRE el status, sea exito o error
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
