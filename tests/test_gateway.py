from __future__ import annotations

import json
import time

from conftest import wait_until
from vchain.fleet import DEVICES
from vchain.node import VirtualVaccineNode


def publish(runtime, node, count: int = 1) -> list[dict]:
    topic = f"vaccine/{node.profile.device_id}/telemetry"
    envelopes = []
    for _ in range(count):
        envelope = node.envelope()
        runtime.publisher.publish(topic, envelope)
        envelopes.append(envelope)
        time.sleep(0.01)
    return envelopes


def test_end_to_end_mqtt_anchoring_under_1_8_seconds(runtime):
    node = VirtualVaccineNode(DEVICES[0], runtime.settings)
    publish(runtime, node, 8)
    assert wait_until(lambda: runtime.store.counts()["readings_anchored"] >= 8, timeout=20)
    snapshot = runtime.snapshot()
    assert snapshot["stats"]["chain_ok"]
    assert snapshot["stats"]["latency"]["n"] >= 8
    assert snapshot["stats"]["latency"]["p95_ms"] < 1800
    assert snapshot["stats"]["readings_rejected"] == 0
    assert runtime.audit.run().ok
    assert runtime.store.counts()["chain_height"] >= 2


def test_duplicate_replay_is_rejected(runtime):
    node = VirtualVaccineNode(DEVICES[0], runtime.settings)
    envelope = node.envelope()
    topic = f"vaccine/{node.profile.device_id}/telemetry"
    runtime.publisher.publish(topic, envelope)
    assert wait_until(lambda: runtime.store.counts()["readings_anchored"] >= 1)
    runtime.publisher.publish(topic, envelope)
    assert wait_until(
        lambda: any(a["kind"] == "DUPLICATE_REPLAY" for a in runtime.store.list_alerts(limit=50))
    )
    assert runtime.store.counts()["readings_anchored"] == 1
    assert runtime.store.counts()["readings_total"] == 1


def test_forged_signature_is_rejected(runtime):
    node = VirtualVaccineNode(DEVICES[0], runtime.settings)
    envelope = node.envelope()
    forged = {**envelope, "signature": "00" * 32}
    runtime.publisher.publish(f"vaccine/{node.profile.device_id}/telemetry", forged)
    assert wait_until(
        lambda: any(a["kind"] == "SIGNATURE_INVALID" for a in runtime.store.list_alerts(limit=50))
    )
    assert runtime.store.counts()["readings_rejected"] == 1
    assert runtime.store.counts()["readings_anchored"] == 0


def test_sequence_replay_is_rejected(runtime):
    node = VirtualVaccineNode(DEVICES[1], runtime.settings)
    publish(runtime, node, 3)
    assert wait_until(lambda: runtime.store.counts()["readings_anchored"] >= 3)
    node.set_seq(0)
    publish(runtime, node, 1)
    assert wait_until(
        lambda: any(a["kind"] == "SEQUENCE_REPLAY" for a in runtime.store.list_alerts(limit=50))
    )
    assert runtime.store.counts()["readings_rejected"] >= 1


def test_excursion_alert_is_committed_into_a_block(runtime):
    node = VirtualVaccineNode(DEVICES[1], runtime.settings)
    node.set_excursion(True)
    publish(runtime, node, 4)
    assert wait_until(
        lambda: any(a["kind"] == "TEMPERATURE_HIGH" for a in runtime.store.list_alerts(limit=50)),
        timeout=20,
    )
    snapshot = runtime.snapshot()
    assert snapshot["stats"]["excursions"] >= 4
    latest = snapshot["blocks"][-1]
    assert latest["excursion_count"] >= 1
    alert = next(a for a in runtime.store.list_alerts(limit=50) if a["kind"] == "TEMPERATURE_HIGH")
    assert alert["block_index"] is not None
    block = runtime.store.get_block(alert["block_index"])
    assert alert["alert_digest"] in json.loads(block["alert_digests_json"])
    assert runtime.audit.run().ok


def test_malformed_payload_is_counted(runtime):
    runtime.publisher.publish_raw("vaccine/VX-001/telemetry", "{not-json", qos=1)
    assert wait_until(lambda: runtime.gateway.malformed >= 1)


def test_digest_mismatch_rejected(runtime):
    node = VirtualVaccineNode(DEVICES[2], runtime.settings)
    envelope = node.envelope()
    envelope["payload"] = {**envelope["payload"], "temperature_centi_c": 999}
    result = runtime.gateway.ingest(envelope, source="http")
    assert not result.accepted
    assert result.reason == "DIGEST_MISMATCH"
    assert any(a["kind"] == "DIGEST_MISMATCH" for a in runtime.store.list_alerts(limit=20))
