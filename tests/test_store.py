from __future__ import annotations

import json

import pytest

from vchain.fleet import DEVICES
from vchain.node import VirtualVaccineNode
from vchain.store import ChainStore


def reading_row(settings, node=None):
    node = node or VirtualVaccineNode(DEVICES[0], settings)
    reading = node.read()
    envelope = reading.envelope(node.device_key)
    return {
        "digest": envelope["digest"],
        "device_id": reading.device_id,
        "seq": reading.seq,
        "measured_at": reading.measured_at,
        "temperature_centi_c": reading.temperature_centi_c,
        "humidity_milli_pct": reading.humidity_milli_pct,
        "lat_e7": reading.lat_e7,
        "lon_e7": reading.lon_e7,
        "gps_fix": reading.gps_fix,
        "firmware": reading.firmware,
        "nonce": reading.nonce,
        "payload_json": json.dumps(envelope["payload"], sort_keys=True, separators=(",", ":")),
        "signature": envelope["signature"],
        "received_at": reading.measured_at,
        "anchored_at": None,
        "block_index": None,
        "status": "pending",
        "source": "test",
        "latency_ms": None,
        "rule_violations_json": "[]",
    }


def test_insert_and_duplicate(settings):
    store = ChainStore(settings.db_path)
    row = reading_row(settings)
    revision = store.revision
    assert store.insert_reading(row) is True
    assert store.insert_reading(row) is False
    assert store.revision > revision
    assert store.reading_exists(row["digest"])
    assert store.get_reading(row["digest"])["device_id"] == "VX-001"
    assert store.pending_count() == 1
    store.close()


def test_device_state_and_last_seq_fallback(settings):
    store = ChainStore(settings.db_path)
    row = reading_row(settings)
    row["seq"] = 7
    store.insert_reading(row)
    assert store.last_seq("VX-001") == 7
    store.set_device_state("VX-001", 9, row["received_at"])
    assert store.last_seq("VX-001") == 9
    assert store.last_seq("VX-999") is None
    store.close()


def test_mutations_are_guarded(settings):
    store = ChainStore(settings.db_path)
    row = reading_row(settings)
    store.insert_reading(row)
    assert store.mutate_reading(row["digest"], {"temperature_centi_c": 350})
    with pytest.raises(ValueError):
        store.mutate_reading(row["digest"], {"drop_table": 1})
    assert store.delete_reading(row["digest"])
    assert not store.delete_reading(row["digest"])
    store.close()


def test_reset_clears_everything(settings):
    store = ChainStore(settings.db_path)
    row = reading_row(settings)
    store.insert_reading(row)
    store.set_meta("hello", {"world": 1})
    revision = store.revision
    store.reset()
    assert store.revision > revision
    assert store.counts()["readings_total"] == 0
    assert store.get_meta("hello") is None
    assert store.block_count() == 0
    store.close()


def test_mutate_block_guard(settings):
    store = ChainStore(settings.db_path)
    with pytest.raises(ValueError):
        store.mutate_block(0, {"evil": 1})
    store.close()


def test_counts_and_latency(settings):
    store = ChainStore(settings.db_path)
    row = reading_row(settings)
    store.insert_reading(row)
    assert store.counts()["readings_pending"] == 1
    store.mark_anchored([(row["digest"], 1, row["received_at"], 42.5)])
    assert store.counts()["readings_anchored"] == 1
    assert store.latency_values() == []  # source is not mqtt
    row2 = reading_row(settings, VirtualVaccineNode(DEVICES[1], settings))
    row2["source"] = "mqtt"
    store.insert_reading(row2)
    store.mark_anchored([(row2["digest"], 1, row2["received_at"], 12.0)])
    assert store.latency_values() == [12.0]
    store.close()
