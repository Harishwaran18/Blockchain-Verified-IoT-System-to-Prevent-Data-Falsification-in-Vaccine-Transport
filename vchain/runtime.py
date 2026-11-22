"""Composition root: wires broker, nodes, gateway, ledger, audit and tamper lab."""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from datetime import timedelta
from .audit import AuditEngine
from .blockchain import Block, genesis_block, reading_proof, validate_chain
from .config import Settings
from .crypto import derive_device_key, derive_validator_key, merkle_root, reading_digest, sign_reading
from .fleet import DEVICES
from .gateway import Gateway, MqttPublisher
from .metrics import BatteryProfile, latency_stats, mean_kinetic_temperature
from .models import epoch_ms, iso_z, utcnow
from .mqtt_broker import EmbeddedBroker
from .node import NodeRunner, VirtualVaccineNode, node_status
from .policy import ColdChainPolicy
from .store import ChainStore
from .tamper import TamperLab

logger = logging.getLogger(__name__)


def _reading_public(row: dict) -> dict:
    return {
        "digest": row["digest"],
        "device_id": row["device_id"],
        "seq": row["seq"],
        "measured_at": row["measured_at"],
        "received_at": row["received_at"],
        "anchored_at": row["anchored_at"],
        "temperature_c": row["temperature_centi_c"] / 100,
        "humidity_pct": row["humidity_milli_pct"] / 1000,
        "lat": row["lat_e7"] / 1e7,
        "lon": row["lon_e7"] / 1e7,
        "gps_fix": bool(row["gps_fix"]),
        "firmware": row["firmware"],
        "block_index": row["block_index"],
        "status": row["status"],
        "source": row["source"],
        "latency_ms": row["latency_ms"],
        "violations": json.loads(row["rule_violations_json"]),
    }


class VChainRuntime:
    def __init__(self, settings: Settings, start_broker: bool = True) -> None:
        self.settings = settings
        self.store = ChainStore(settings.db_path)
        self.policy = ColdChainPolicy.from_settings(settings)
        self.validators = [
            {"id": f"validator-{i + 1}", "key": derive_validator_key(settings.master_secret, i + 1)}
            for i in range(settings.validator_count)
        ]
        self.quorum = settings.quorum
        self.gateway = Gateway(self.store, settings, self.policy, self.validators, self.quorum)
        self.audit = AuditEngine(self.store, settings, self.policy, self.validators, self.quorum)
        self.tamper = TamperLab(self.store, settings, self.audit, self.gateway)
        self.nodes: dict[str, VirtualVaccineNode] = {
            profile.device_id: VirtualVaccineNode(profile, settings) for profile in DEVICES
        }
        self.runners: dict[str, NodeRunner] = {}
        self.publisher: MqttPublisher | None = None
        self.broker: EmbeddedBroker | None = None
        self.broker_enabled = start_broker
        self.started_at = utcnow()
        self._running = False
        self._lock = threading.RLock()
        self._chain_cache: tuple[float, list] | None = None
        self._init_chain()

    # --------------------------------------------------------------- lifecycle
    def _init_chain(self) -> None:
        if self.store.block_count() == 0:
            block = genesis_block(
                self.policy.to_dict(), self.settings.difficulty, self.validators
            )
            self.store.insert_block(block.to_row(synthetic=1))
            self.store.set_meta("genesis_hash", block.hash)
            logger.info("Initialised genesis block %s", block.hash[:16])

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            if self.broker_enabled:
                self.broker = EmbeddedBroker(self.settings.mqtt_host, self.settings.mqtt_port)
                try:
                    self.broker.start()
                except Exception as exc:
                    self.broker = None
                    logger.warning(
                        "Embedded broker unavailable (%s); assuming an external broker on %s:%s",
                        exc,
                        self.settings.mqtt_host,
                        self.settings.mqtt_port,
                    )
            if self.settings.seed_demo and self.store.counts()["readings_total"] == 0:
                self.seed_demo()
            self._start_pipeline()
            self._running = True
            self.started_at = utcnow()

    def _start_pipeline(self) -> None:
        connected = self.gateway.start(wait=True, timeout=10)
        if not connected:
            logger.warning("Gateway could not subscribe to MQTT broker yet; will retry in background")
        self.publisher = MqttPublisher(self.settings.mqtt_host, self.settings.mqtt_port)
        if not self.publisher.start(timeout=10):
            logger.warning("Node publisher not connected yet; nodes will retry publishes")
        if self.settings.start_nodes:
            for device_id, node in self.nodes.items():
                last_seq = self.store.last_seq(device_id)
                node.set_seq(last_seq + 1 if last_seq is not None else 0)
                runner = NodeRunner(
                    node,
                    self.publisher.publish,
                    interval_s=self.settings.node_interval_s,
                )
                runner.start()
                self.runners[device_id] = runner

    def stop(self, close_store: bool = False) -> None:
        with self._lock:
            for runner in self.runners.values():
                runner.stop()
            for runner in self.runners.values():
                runner.join(timeout=3)
            self.runners.clear()
            if self.publisher:
                self.publisher.stop()
                self.publisher = None
            self.gateway.stop()
            if self.broker:
                self.broker.stop()
                self.broker = None
            self._running = False
            if close_store:
                self.store.close()

    def reset(self) -> dict:
        with self._lock:
            was_running = self._running
            for runner in self.runners.values():
                runner.stop()
            for runner in self.runners.values():
                runner.join(timeout=3)
            self.runners.clear()
            if self.publisher:
                self.publisher.stop()
                self.publisher = None
            self.gateway.stop()
            self.store.reset()
            self._init_chain()
            for node in self.nodes.values():
                node.reset()
            if self.settings.seed_demo:
                self.seed_demo()
            self._chain_cache = None
            self.started_at = utcnow()
            if was_running:
                self._start_pipeline()
                self._running = True
            logger.info("Demo ledger reset; genesis re-created")
            return {"ok": True, "genesis_hash": self.store.get_meta("genesis_hash")}

    # ----------------------------------------------------------------- seeding
    def seed_demo(self, readings_per_device: int = 14) -> None:
        now = utcnow()
        for profile in DEVICES:
            node = VirtualVaccineNode(
                profile,
                self.settings,
                rng=random.Random(profile.device_id),
            )
            for index in range(readings_per_device):
                measured = now - timedelta(seconds=(readings_per_device - index) * 30)
                node.set_excursion(profile.device_id == "VX-002" and 5 <= index <= 7)
                reading = node.read(now=measured)
                self.gateway.ingest(
                    reading.envelope(node.device_key), source="seed", received_at=now
                )
        self.gateway.flush(force=True)
        logger.info("Seeded %d synthetic readings across %d devices", readings_per_device * len(DEVICES), len(DEVICES))

    # ------------------------------------------------------------------- state
    def chain_issues(self) -> list:
        revision = self.store.revision
        if self._chain_cache and self._chain_cache[0] == revision:
            return self._chain_cache[1]
        issues = validate_chain(self.store.all_blocks(), self.validators, self.quorum)
        self._chain_cache = (revision, issues)
        return issues

    def snapshot(self) -> dict:
        counts = self.store.counts()
        alerts = self.store.alert_counts()
        tamper = self.store.tamper_stats()
        latency = latency_stats(self.store.latency_values())
        issues = self.chain_issues()
        last_by_device = self.store.device_last_readings()
        alerts_by_device = self.store.alert_counts_by_device()
        now = utcnow()

        devices = []
        for profile in DEVICES:
            node = self.nodes[profile.device_id]
            last = last_by_device.get(profile.device_id)
            status = node_status(node, last)
            runner = self.runners.get(profile.device_id)
            temperatures = self.store.device_temperatures(profile.device_id, 120)
            mkt = mean_kinetic_temperature(temperatures)
            alert_entry = alerts_by_device.get(profile.device_id, {})
            status.update(
                {
                    "mkt_c": round(mkt, 2) if mkt is not None else None,
                    "readings_anchored": self.store.device_readings_count(profile.device_id),
                    "excursions": alert_entry.get("excursions", 0),
                    "warnings": alert_entry.get("warnings", 0),
                    "online": bool(runner and runner.is_alive()),
                    "last_error": runner.last_error if runner else None,
                    "battery_profile": node.battery.to_dict(),
                }
            )
            devices.append(status)

        blocks = []
        for row in self.store.all_blocks()[-10:]:
            block = Block.from_row(row)
            public = block.to_public()
            public["mine_ms"] = row["mine_ms"]
            public["synthetic"] = bool(row["synthetic"])
            blocks.append(public)

        series = {
            device_id: [
                {"t": epoch_ms(point["measured_at"]), "temp": point["temperature_c"]}
                for point in points
            ]
            for device_id, points in self.store.temperature_history(40).items()
        }

        latest_audit = self.audit.latest()
        detection_rate = (tamper["detected"] / tamper["total"]) if tamper["total"] else None

        return {
            "now": iso_z(now),
            "network": {
                "mqtt_connected": self.gateway.connected.is_set(),
                "mqtt_host": self.settings.mqtt_host,
                "mqtt_port": self.settings.mqtt_port,
                "broker": "embedded" if self.broker and self.broker.running else "external",
                "nodes_online": sum(1 for runner in self.runners.values() if runner.is_alive()),
                "nodes_total": len(self.nodes),
                "started_at": iso_z(self.started_at),
                "uptime_s": int((now - self.started_at).total_seconds()),
            },
            "stats": {
                **counts,
                "alerts_total": alerts["total"],
                "alerts_critical": alerts["critical"],
                "excursions": alerts["excursions"],
                "tamper_attempts": tamper["total"],
                "tamper_detected": tamper["detected"],
                "detection_rate": detection_rate,
                "latency": latency,
                "chain_ok": not issues,
                "chain_issue_count": len(issues),
                "last_audit_ok": latest_audit["ok"] if latest_audit else None,
                "last_audit_at": latest_audit["finished_at"] if latest_audit else None,
            },
            "policy": {
                "min_temp_c": self.policy.min_temp_c,
                "max_temp_c": self.policy.max_temp_c,
                "humidity_min_pct": self.policy.humidity_min_pct,
                "humidity_max_pct": self.policy.humidity_max_pct,
                "block_size": self.settings.block_size,
                "block_interval_s": self.settings.block_interval_s,
                "difficulty": self.settings.difficulty,
                "validators": len(self.validators),
                "quorum": self.quorum,
                "hash": "SHA-256",
                "signature": "HMAC-SHA256",
                "merkle": "SHA-256 (domain-separated)",
            },
            "battery": BatteryProfile(
                capacity_mah=self.settings.battery_capacity_mah,
                active_current_ma=self.settings.battery_active_ma,
                sleep_current_ma=self.settings.battery_sleep_ma,
                active_seconds=self.settings.battery_active_s,
                interval_seconds=self.settings.node_field_interval_s,
                derating=self.settings.battery_derating,
            ).to_dict(),
            "devices": devices,
            "readings": [_reading_public(row) for row in self.store.list_readings(limit=40)],
            "blocks": blocks,
            "alerts": [
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "severity": row["severity"],
                    "device_id": row["device_id"],
                    "reading_digest": row["reading_digest"],
                    "message": row["message"],
                    "created_at": row["created_at"],
                    "block_index": row["block_index"],
                    "alert_digest": row["alert_digest"],
                }
                for row in self.store.list_alerts(limit=30)
            ],
            "series": series,
            "audit": latest_audit,
            "tamper_events": [
                {
                    "id": row["id"],
                    "attack": row["attack"],
                    "description": row["description"],
                    "created_at": row["created_at"],
                    "detected": bool(row["detected"]),
                }
                for row in self.store.list_tamper_events(limit=8)
            ],
            "attacks": self.tamper.list_attacks(),
            "chain_issues": [issue.to_dict() for issue in issues[:20]],
        }

    # ------------------------------------------------------------------ detail
    def reading_detail(self, digest: str) -> dict | None:
        row = self.store.get_reading(digest)
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        key = derive_device_key(self.settings.master_secret, row["device_id"])
        block_row = self.store.get_block(row["block_index"]) if row["block_index"] is not None else None
        block = Block.from_row(block_row) if block_row else None
        proof = None
        checks = {
            "payload_digest_ok": reading_digest(payload) == digest,
            "signature_ok": sign_reading(key, digest) == row["signature"],
            "merkle_ok": False,
            "block_hash_ok": False,
            "proof_of_work_ok": False,
            "validator_quorum_ok": False,
            "anchored": row["status"] == "anchored",
        }
        if block is not None:
            checks["block_hash_ok"] = block.compute_hash() == block.hash
            checks["proof_of_work_ok"] = block.hash.startswith("0" * block.difficulty)
            valid, _ = block.signature_report(self.validators, self.quorum)
            checks["validator_quorum_ok"] = valid >= self.quorum
            if digest in block.digests:
                proof = reading_proof(digest, block)
                checks["merkle_ok"] = bool(proof["verified"])
        checks["verified"] = all(checks.values())
        return {
            "reading": _reading_public(row),
            "payload": payload,
            "signature": row["signature"],
            "block": block.to_public() if block else None,
            "proof": proof,
            "checks": checks,
        }

    def block_detail(self, index: int) -> dict | None:
        row = self.store.get_block(index)
        if row is None:
            return None
        block = Block.from_row(row)
        valid, invalid = block.signature_report(self.validators, self.quorum)
        readings = [_reading_public(r) for r in self.store.readings_for_block(index)]
        alerts = [
            alert for alert in self.store.all_alerts() if alert["block_index"] == index
        ]
        previous = self.store.get_block(index - 1) if index > 0 else None
        checks = {
            "block_hash_ok": block.compute_hash() == block.hash,
            "merkle_ok": block.merkle_root == merkle_root(block.digests),
            "proof_of_work_ok": block.hash.startswith("0" * block.difficulty),
            "validator_signatures_valid": valid,
            "validator_quorum_ok": valid >= self.quorum,
            "prev_link_ok": previous is None or block.prev_hash == previous["hash"],
            "readings_present": len(readings) == len(block.digests),
        }
        return {
            "block": {**block.to_public(), "mine_ms": row["mine_ms"], "nonce": block.nonce},
            "readings": readings,
            "alerts": [
                {
                    "id": a["id"],
                    "kind": a["kind"],
                    "severity": a["severity"],
                    "message": a["message"],
                    "device_id": a["device_id"],
                }
                for a in alerts
            ],
            "checks": checks,
            "invalid_validators": invalid,
        }

    def export_bundle(self) -> dict:
        return {
            "generated_at": iso_z(utcnow()),
            "system": "VChain cold-chain ledger",
            "genesis_hash": self.store.get_meta("genesis_hash"),
            "policy": self.policy.to_dict(),
            "chain_height": self.store.counts()["chain_height"],
            "audit": self.audit.latest(),
            "chain_issues": [issue.to_dict() for issue in self.chain_issues()],
            "blocks": [Block.from_row(row).to_public() for row in self.store.all_blocks()],
            "readings": [
                {
                    "digest": row["digest"],
                    "device_id": row["device_id"],
                    "seq": row["seq"],
                    "measured_at": row["measured_at"],
                    "temperature_c": row["temperature_centi_c"] / 100,
                    "block_index": row["block_index"],
                    "status": row["status"],
                    "signature": row["signature"],
                }
                for row in self.store.all_readings()
            ],
            "alerts": self.store.all_alerts(),
            "tamper_events": self.store.list_tamper_events(limit=100),
        }

    def set_excursion(self, device_id: str, active: bool) -> dict:
        node = self.nodes.get(device_id)
        if node is None:
            raise KeyError(device_id)
        node.set_excursion(active)
        return {"device_id": device_id, "excursion_active": node.excursion_active}


def default_runtime(settings: Settings | None = None) -> VChainRuntime:
    return VChainRuntime(settings or Settings.from_env())
