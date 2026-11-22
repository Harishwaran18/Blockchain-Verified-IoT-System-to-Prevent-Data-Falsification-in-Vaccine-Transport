from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vchain.crypto import canonical_json

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "firmware" / "test" / "test_canonical.cpp"


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ is not installed")
def test_cpp_and_python_canonical_encoders_match(tmp_path):
    binary = tmp_path / "test_canonical"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", str(SOURCE), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    lines = subprocess.check_output([str(binary)], text=True).strip().splitlines()
    assert len(lines) == 3

    first = {
        "device_id": "VX-001",
        "firmware": "1.0.0",
        "gps_fix": 1,
        "humidity_milli_pct": 45250,
        "lat_e7": 407128000,
        "lon_e7": -740059000,
        "measured_at": "2026-11-22T09:10:00.123Z",
        "nonce": "a1b2c3d4e5f60718",
        "seq": 42,
        "temperature_centi_c": 512,
    }
    second = {
        "device_id": "VX-002",
        "firmware": "1.0.0",
        "gps_fix": 0,
        "humidity_milli_pct": 0,
        "lat_e7": -1,
        "lon_e7": -2,
        "measured_at": "2026-01-01T00:00:00.000Z",
        "nonce": "0000000000000000",
        "seq": 0,
        "temperature_centi_c": -1250,
    }
    assert lines[0] == canonical_json(first).decode()
    assert lines[1] == canonical_json(second).decode()
    assert lines[2] == json.dumps(
        {"alg": "HMAC-SHA256", "digest": "aa", "payload": {}, "signature": "bb"},
        separators=(",", ":"),
        sort_keys=True,
    )
