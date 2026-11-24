"""Live alert stream exposed over HTTP (Server-Sent Events)."""

import asyncio
import logging

from aiohttp import web

logger = logging.getLogger("vigil.stream")

KEEPALIVE_SECONDS = 15.0
CLIENT_QUEUE_SIZE = 1000


class AlertBroadcaster:
    """Fan each alert out to every connected client without ever blocking."""

    def __init__(self, client_queue_size: int = CLIENT_QUEUE_SIZE) -> None:
        self._client_queue_size = client_queue_size
        self._clients: set[asyncio.Queue[str]] = set()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._client_queue_size)
        self._clients.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._clients.discard(queue)

    def publish(self, alert: str) -> None:
        """Push an alert to each client queue; drop it for a client whose queue is full."""
        for queue in self._clients:
            try:
                queue.put_nowait(alert)
            except asyncio.QueueFull:
                logger.warning("Slow client, alert dropped")


class StreamServer:
    """HTTP server with ``GET /stream`` (SSE) and ``GET /health``."""

    def __init__(
        self,
        broadcaster: AlertBroadcaster,
        host: str = "127.0.0.1",
        port: int = 8000,
        keepalive: float = KEEPALIVE_SECONDS,
    ) -> None:
        self._broadcaster = broadcaster
        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        app = web.Application()
        app.add_routes([web.get("/stream", self._stream), web.get("/health", self._health)])
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, self._host, self._port).start()
        logger.info("Stream listening on http://%s:%d/stream", self._host, self._port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def _health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "clients": self._broadcaster.client_count})

    async def _stream(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )
        await response.prepare(request)
        queue = self._broadcaster.subscribe()
        try:
            await response.write(b": connected\n\n")
            while True:
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=self._keepalive)
                except asyncio.TimeoutError:
                    await response.write(b": keepalive\n\n")
                    continue
                await response.write(f"data: {alert}\n\n".encode("utf-8"))
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            self._broadcaster.unsubscribe(queue)
        return response
