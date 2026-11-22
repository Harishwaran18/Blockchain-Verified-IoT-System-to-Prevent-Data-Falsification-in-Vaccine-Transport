"""Embedded MQTT 3.1.1 broker so the demo runs with no external services."""

from __future__ import annotations

import asyncio
import logging
import threading

logger = logging.getLogger(__name__)


class EmbeddedBroker:
    def __init__(self, host: str = "127.0.0.1", port: int = 1883) -> None:
        self.host = host
        self.port = port
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._broker = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._ready.is_set()

    def start(self, timeout: float = 10.0) -> None:
        from amqtt.broker import Broker

        config = {
            "listeners": {
                "default": {
                    "type": "tcp",
                    "bind": f"{self.host}:{self.port}",
                    "max_connections": 128,
                }
            },
            "plugins": {
                "amqtt.plugins.authentication.AnonymousAuthPlugin": {"allow_anonymous": True}
            },
            "topic-check": {"enabled": False},
            "sys_interval": 0,
        }

        def run() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                broker = Broker(config, loop=loop)
                self._broker = broker
                loop.run_until_complete(broker.start())
                self._ready.set()
                loop.run_forever()
            except BaseException as exc:  # surface bind/auth failures to the caller
                self._error = exc
                self._ready.set()

        self._thread = threading.Thread(target=run, name="mqtt-broker", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError(f"MQTT broker did not start within {timeout}s")
        if self._error is not None:
            raise RuntimeError(f"MQTT broker failed: {self._error}") from self._error
        logger.info("Embedded MQTT broker listening on %s:%s", self.host, self.port)

    def stop(self, timeout: float = 10.0) -> None:
        if not self._loop or not self._broker:
            return
        try:
            future = asyncio.run_coroutine_threadsafe(self._broker.shutdown(), self._loop)
            future.result(timeout=timeout)
        except Exception as exc:  # pragma: no cover - shutdown best effort
            logger.debug("Broker shutdown issue: %s", exc)
        finally:
            if self._loop.is_running():
                self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread:
                self._thread.join(timeout=timeout)
            self._ready.clear()
            logger.info("Embedded MQTT broker stopped")
