"""Middleware ASGI que limita el tamaño del body HTTP.

Protege contra bodies gigantes o chunked sin Content-Length (relleno de
memoria/disco en /alerts, /simulate, config/update, etc.). Funciona como
middleware puro ASGI (no BaseHTTPMiddleware) para poder envolver `receive`
sin consumir el body que luego leerán los handlers.
"""

from collections.abc import Awaitable, Callable

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]

_MAX_413 = (
    b'{"error":"payload too large"}'
)


class BodyTooLarge(BaseException):
    """Se lanza cuando el body supera max_bytes.

    Hereda de BaseException (como asyncio.CancelledError) para que la
    atraviese los `except Exception` de los handlers (p. ej. el de JSON
    inválido en /alerts) y llegue al middleware que responde 413. Si
    heredara de Exception, los endpoints la convertirían en 400/500.
    """

    pass


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Rechazo rápido por Content-Length, antes de leer un solo byte
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True  # header basura -> no confiar en él
                if too_big:
                    await self._send_413(send)
                    return
                break

        total = 0
        responded = False

        async def guarded_receive() -> dict:
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise BodyTooLarge()
            return message

        async def tracking_send(message: dict) -> None:
            nonlocal responded
            if message["type"] in ("http.response.start", "http.response.body"):
                responded = True
            await send(message)

        try:
            await self.app(scope, guarded_receive, tracking_send)
        except BodyTooLarge:
            if responded:
                # La respuesta ya empezó: solo propagar y dejar que
                # uvicorn corte la conexión.
                raise
            await self._send_413(send)

    @staticmethod
    async def _send_413(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_MAX_413)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _MAX_413})
