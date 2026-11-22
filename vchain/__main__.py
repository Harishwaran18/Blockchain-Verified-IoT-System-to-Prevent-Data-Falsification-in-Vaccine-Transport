"""Command line entry point: python -m vchain."""

from __future__ import annotations

import argparse
import logging
import os
from dataclasses import replace
from pathlib import Path

from .api import create_app
from .config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="VChain cold-chain ledger")
    parser.add_argument("--host", default=None, help="API bind address")
    parser.add_argument("--port", type=int, default=None, help="API port")
    parser.add_argument("--mqtt-port", type=int, default=None, help="MQTT broker port")
    parser.add_argument("--no-nodes", action="store_true", help="do not start simulated nodes")
    parser.add_argument("--no-broker", action="store_true", help="use an external MQTT broker")
    parser.add_argument("--no-seed", action="store_true", help="start with an empty ledger")
    parser.add_argument("--fresh", action="store_true", help="delete the existing database first")
    parser.add_argument("--log-level", default=None)
    args = parser.parse_args()

    settings = Settings.from_env()
    updates = {}
    if args.host:
        updates["api_host"] = args.host
    if args.port:
        updates["api_port"] = args.port
    if args.mqtt_port:
        updates["mqtt_port"] = args.mqtt_port
    if args.no_nodes:
        updates["start_nodes"] = False
    if args.no_seed:
        updates["seed_demo"] = False
    if args.log_level:
        updates["log_level"] = args.log_level.upper()
    settings = replace(settings, **updates)

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    if args.fresh:
        for suffix in ("", "-wal", "-shm"):
            Path(str(settings.db_path) + suffix).unlink(missing_ok=True)

    import uvicorn

    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
