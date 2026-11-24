"""Alert delivery to the terminal and the live stream."""

import sys

from src.output.stream_server import AlertBroadcaster


class AlertDispatcher:
    """Write alerts to stdout and publish them to the stream clients."""

    def __init__(
        self,
        to_terminal: bool = True,
        broadcaster: AlertBroadcaster | None = None,
    ) -> None:
        self._to_terminal = to_terminal
        self._broadcaster = broadcaster

    async def dispatch(self, alert: str) -> None:
        """Emit an alert to every configured output."""
        if self._to_terminal:
            print(alert, file=sys.stdout, flush=True)
        if self._broadcaster is not None:
            self._broadcaster.publish(alert)
