from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vchain.config import Settings  # noqa: E402
from vchain.fleet import DEVICES  # noqa: E402
from vchain.node import VirtualVaccineNode  # noqa: E402
from vchain.runtime import VChainRuntime  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(predicate, timeout: float = 12.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "vchain-test.db",
        mqtt_host="127.0.0.1",
        mqtt_port=free_port(),
        block_size=4,
        block_interval_s=0.2,
        difficulty=2,
        validator_count=3,
        quorum=2,
        seed_demo=False,
        start_nodes=False,
        node_interval_s=0.05,
        master_secret="test-master-secret",
    )


@pytest.fixture
def runtime(settings):
    instance = VChainRuntime(settings)
    instance.start()
    try:
        yield instance
    finally:
        instance.stop(close_store=True)


@pytest.fixture
def sample_reading():
    node = VirtualVaccineNode(DEVICES[0], Settings(master_secret="test-master-secret"))
    return node.read()


@pytest.fixture
def sample_envelope(sample_reading):
    node_key = VirtualVaccineNode(
        DEVICES[0], Settings(master_secret="test-master-secret")
    ).device_key
    return sample_reading.envelope(node_key)
