"""MQTT ingest, signature verification, batching and ledger anchoring."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

import paho.mqtt.client as mqtt

from .blockchain import build_block
from .config import Settings
from .crypto import derive_device_key
from .models import Alert, SignedEnvelope, TelemetryReading, iso_z, parse_iso, utcnow
from .policy import ColdChainPolicy, PolicyViolation
from .store import ChainStore

logger = logging.getLogger(__name__)


@dataclass
class IngestResult:
    accepted: bool
    digest: str | None = None
    device_id: str | None = None
    reason: str | None = None
    violations: list[dict] = field(default_factory=list)


class MqttPublisher:
    """QoS-1 publisher used by the virtual nodes."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._connected = threading.Event()
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"vchain-node-{os.getpid()}-{int(time.time() * 1000) % 100000}",
        )
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.reconnect_delay_set(min_delay=1, max_delay=10)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            self._connected.set()
        else:
            logger.warning("Node publisher connect failed: %s", reason_code)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self._connected.clear()

    def start(self, timeout: float = 10.0) -> bool:
        self._client.connect_async(self.host, self.port, keepalive=30)
        self._client.loop_start()
        return self._connected.wait(timeout)

    def publish(self, topic: str, payload: dict) -> None:
        self.publish_raw(topic, json.dumps(payload, separators=(",", ":")), qos=1)

    def publish_raw(self, topic: str, payload: str | bytes, qos: int = 1) -> None:
        if not self._connected.is_set():
            raise RuntimeError("MQTT publisher is not connected")
        info = self._client.publish(topic, payload, qos=qos)
        info.wait_for_publish(timeout=5)

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def stop(self) -> None:
        self._connected.clear()
        self._client.loop_stop()
        self._client.disconnect()


class Gateway:
    def __init__(
        self,
        store: ChainStore,
        settings: Settings,
        policy: ColdChainPolicy | None = None,
        validators: list[dict] | None = None,
        quorum: int | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.policy = policy or ColdChainPolicy.from_settings(settings)
        self.validators = validators or []
        self.quorum = quorum or settings.quorum
        self.connected = threading.Event()
        self.malformed = 0
        self.last_error: str | None = None
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._flush_thread: threading.Thread | None = None
        self._client: mqtt.Client | None = None

    # --------------------------------------------------------------- MQTT I/O
    def start(self, wait: bool = True, timeout: float = 10.0) -> bool:
        self._stop.clear()
        self.connected.clear()
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=f"vchain-gateway-{os.getpid()}"
        )
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message
        self._client.reconnect_delay_set(min_delay=1, max_delay=10)
        self._client.connect_async(self.settings.mqtt_host, self.settings.mqtt_port, keepalive=30)
        self._client.loop_start()
        self._flush_thread = threading.Thread(target=self._flush_loop, name="gateway-flush", daemon=True)
        self._flush_thread.start()
        if wait:
            return self.connected.wait(timeout)
        return True

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            client.subscribe(self.settings.mqtt_topic, qos=1)
            self.connected.set()
            logger.info("Gateway subscribed to %s", self.settings.mqtt_topic)
        else:
            logger.warning("Gateway connect failed: %s", reason_code)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self.connected.clear()
        if reason_code == 0:
            logger.info("Gateway disconnected from broker")
        else:
            logger.warning("Gateway disconnected from broker: %s", reason_code)

    def _on_message(self, client, userdata, message):
        try:
            data = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.malformed += 1
            self.last_error = f"malformed MQTT payload: {exc}"
            logger.warning(self.last_error)
            return
        result = self.ingest(data, source="mqtt")
        if not result.accepted:
            logger.info("Rejected %s from %s: %s", result.digest, result.device_id, result.reason)

    # --------------------------------------------------------------- ingest
    def ingest(
        self,
        envelope_data: dict | SignedEnvelope,
        source: str = "mqtt",
        received_at: datetime | None = None,
    ) -> IngestResult:
        received = received_at or utcnow()
        try:
            envelope = (
                envelope_data
                if isinstance(envelope_data, SignedEnvelope)
                else SignedEnvelope.from_dict(envelope_data)
            )
            reading = envelope.reading
        except ValueError as exc:
            self.malformed += 1
            self.last_error = f"schema rejection: {exc}"
            return IngestResult(accepted=False, reason=f"SCHEMA_INVALID: {exc}")

        device_key = derive_device_key(self.settings.master_secret, reading.device_id)

        if not envelope.check_digest():
            self._reject(
                envelope,
                reading,
                source,
                received,
                "DIGEST_MISMATCH",
                "critical",
                "payload digest does not match the declared SHA-256 digest",
            )
            return IngestResult(False, envelope.digest, reading.device_id, "DIGEST_MISMATCH")

        if not envelope.check_signature(device_key):
            self._reject(
                envelope,
                reading,
                source,
                received,
                "SIGNATURE_INVALID",
                "critical",
                "HMAC-SHA256 device signature verification failed",
            )
            return IngestResult(False, envelope.digest, reading.device_id, "SIGNATURE_INVALID")

        if self.store.reading_exists(envelope.digest):
            self._alert_once(
                reading,
                envelope.digest,
                received,
                "DUPLICATE_REPLAY",
                "warning",
                "identical signed reading was already received; replay rejected",
            )
            return IngestResult(False, envelope.digest, reading.device_id, "DUPLICATE")

        previous_seq = self.store.last_seq(reading.device_id)
        violations = self.policy.evaluate(reading, previous_seq, now=received)
        codes = {v.code for v in violations}

        if "SEQUENCE_REPLAY" in codes:
            self._reject(
                envelope,
                reading,
                source,
                received,
                "SEQUENCE_REPLAY",
                "critical",
                f"sequence {reading.seq} was already used for {reading.device_id}",
                violations=violations,
            )
            return IngestResult(False, envelope.digest, reading.device_id, "SEQUENCE_REPLAY", _violations(violations))

        row = self._reading_row(envelope, reading, received, "pending", source, violations)
        inserted = self.store.insert_reading(row)
        if not inserted:
            return IngestResult(False, envelope.digest, reading.device_id, "DUPLICATE")

        for violation in violations:
            self._alert(reading, envelope.digest, received, violation.code, violation.severity, violation.message)
        self.store.set_device_state(reading.device_id, reading.seq, iso_z(received))

        if self.store.pending_count() >= self.settings.block_size:
            self.flush(force=True)
        return IngestResult(True, envelope.digest, reading.device_id, None, _violations(violations))

    def _reject(
        self,
        envelope: SignedEnvelope,
        reading: TelemetryReading,
        source: str,
        received: datetime,
        reason: str,
        severity: str,
        message: str,
        violations: list[PolicyViolation] | None = None,
    ) -> None:
        row = self._reading_row(envelope, reading, received, "rejected", source, violations or [])
        self.store.insert_reading(row)
        self._alert_once(reading, envelope.digest, received, reason, severity, message)

    def _reading_row(
        self,
        envelope: SignedEnvelope,
        reading: TelemetryReading,
        received: datetime,
        status: str,
        source: str,
        violations: list[PolicyViolation],
    ) -> dict:
        return {
            "digest": envelope.digest,
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
            "payload_json": json.dumps(envelope.payload, sort_keys=True, separators=(",", ":")),
            "signature": envelope.signature,
            "received_at": iso_z(received),
            "anchored_at": None,
            "block_index": None,
            "status": status,
            "source": source,
            "latency_ms": None,
            "rule_violations_json": json.dumps(_violations(violations)),
        }

    def _alert(
        self,
        reading: TelemetryReading,
        digest: str,
        created: datetime,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        alert = Alert(
            kind=kind,
            severity=severity,
            device_id=reading.device_id,
            reading_digest=digest,
            message=message,
            created_at=iso_z(created),
        )
        self.store.insert_alert({**alert.to_dict(), "block_index": None})

    def _alert_once(
        self,
        reading: TelemetryReading,
        digest: str,
        created: datetime,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        if any(a["kind"] == kind for a in self.store.alerts_for_digests([digest])):
            return
        self._alert(reading, digest, created, kind, severity, message)

    # ---------------------------------------------------------------- batching
    def flush(self, force: bool = False) -> dict | None:
        with self._flush_lock:
            pending = self.store.pending_readings(self.settings.block_size)
            if not pending:
                return None
            if not force and len(pending) < self.settings.block_size:
                oldest = parse_iso(pending[0]["received_at"])
                if (utcnow() - oldest).total_seconds() < self.settings.block_interval_s:
                    return None

            digests = [row["digest"] for row in pending]
            alerts = self.store.alerts_for_digests(digests)
            latest = self.store.latest_block()
            if latest is None:
                raise RuntimeError("ledger has no genesis block")
            block, mine_ms = build_block(
                index=latest["idx"] + 1,
                prev_hash=latest["hash"],
                digests=digests,
                alert_digests=[a["alert_digest"] for a in alerts],
                excursion_count=sum(
                    1 for a in alerts if a["kind"] in ("TEMPERATURE_HIGH", "TEMPERATURE_LOW")
                ),
                policy=self.policy.to_dict(),
                difficulty=self.settings.difficulty,
                validators=self.validators,
            )
            self.store.insert_block(block.to_row(mine_ms=mine_ms))
            anchored_at = block.created_at
            entries = []
            for row in pending:
                latency = (parse_iso(anchored_at) - parse_iso(row["received_at"])).total_seconds() * 1000
                entries.append((row["digest"], block.index, anchored_at, round(latency, 3)))
            self.store.mark_anchored(entries)
            self.store.set_alerts_block([a["alert_digest"] for a in alerts], block.index)
            logger.info(
                "Anchored block %d: %d readings, %d alerts, nonce %d, mine %.1f ms",
                block.index,
                len(digests),
                len(alerts),
                block.nonce,
                mine_ms,
            )
            return {
                "index": block.index,
                "hash": block.hash,
                "merkle_root": block.merkle_root,
                "readings": len(digests),
                "alerts": len(alerts),
                "mine_ms": round(mine_ms, 3),
            }

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush(force=False)
            except Exception as exc:  # keep the anchor service alive
                self.last_error = f"flush error: {type(exc).__name__}: {exc}"
                logger.exception("Flush failed")
            self._stop.wait(0.2)

    def stop(self) -> None:
        self._stop.set()
        self.connected.clear()
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        try:
            self.flush(force=True)
        except Exception:
            logger.exception("Final flush failed")


def _violations(violations: list[PolicyViolation]) -> list[dict]:
    return [v.to_dict() for v in violations]
