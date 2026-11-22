"""Adversarial tamper lab.

Each attack emulates a realistic falsification attempt against the off-chain
database or the wire protocol. The audit engine must detect every one of them.
Attacks are destructive on purpose: the UI keeps the evidence visible until the
demo is reset.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .audit import AuditEngine, AuditReport
from .blockchain import Block
from .config import Settings
from .crypto import derive_device_key, merkle_root, new_nonce, reading_digest, sign_reading
from .gateway import Gateway
from .models import iso_z, utcnow
from .store import ChainStore


@dataclass(frozen=True)
class AttackInfo:
    key: str
    name: str
    description: str
    layer: str


ATTACKS: list[AttackInfo] = [
    AttackInfo(
        "edit_temperature",
        "Naive temperature edit",
        "An insider rewrites a stored 9.4 °C excursion down to 3.5 °C in the database, leaving the original digest and signature in place.",
        "off-chain database",
    ),
    AttackInfo(
        "resign_edit",
        "Re-signed falsification",
        "An attacker with the device key re-hashes and re-signs a falsified reading and replaces the database row, but cannot change the block that already committed the original digest.",
        "off-chain database + stolen key",
    ),
    AttackInfo(
        "forge_reading",
        "Forged anchored reading",
        "An attacker injects a fabricated reading straight into the database and marks it anchored to the latest block.",
        "off-chain database",
    ),
    AttackInfo(
        "delete_reading",
        "Evidence deletion",
        "An operator deletes an inconvenient reading row that a block already committed to.",
        "off-chain database",
    ),
    AttackInfo(
        "rewrite_block",
        "Ledger rewrite",
        "An attacker edits a block to erase a reading, recomputes its Merkle root and hash, but cannot re-mine proof-of-work or forge the validator quorum.",
        "ledger database",
    ),
    AttackInfo(
        "replay",
        "Signed replay",
        "A previously accepted signed packet is replayed to the MQTT topic to double-count a compliant reading.",
        "MQTT wire",
    ),
]


class TamperLab:
    def __init__(
        self,
        store: ChainStore,
        settings: Settings,
        audit: AuditEngine,
        gateway: Gateway | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.audit = audit
        self.gateway = gateway
        self.attacks = {attack.key: attack for attack in ATTACKS}

    def list_attacks(self) -> list[dict]:
        return [
            {
                "key": attack.key,
                "name": attack.name,
                "description": attack.description,
                "layer": attack.layer,
            }
            for attack in ATTACKS
        ]

    def run(self, key: str) -> dict:
        attack = self.attacks.get(key)
        if attack is None:
            raise KeyError(f"unknown attack {key!r}")
        started = time.perf_counter()
        baseline = self.audit.run(persist=False).failures
        if key == "edit_temperature":
            description = self._edit_temperature()
        elif key == "resign_edit":
            description = self._resign_edit()
        elif key == "forge_reading":
            description = self._forge_reading()
        elif key == "delete_reading":
            description = self._delete_reading()
        elif key == "rewrite_block":
            description = self._rewrite_block()
        else:
            description = self._replay()

        report: AuditReport = self.audit.run()
        if key == "replay":
            failures = [
                {
                    "kind": "REPLAY_REJECTED",
                    "severity": "critical",
                    "block_index": None,
                    "detail": description,
                    "expected": None,
                    "actual": None,
                }
            ] if self._last_replay_rejected else report.failures
            detected = self._last_replay_rejected
        else:
            new_failures = [failure for failure in report.failures if failure not in baseline]
            failures = new_failures or report.failures
            detected = not report.ok

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        self.store.insert_tamper_event(
            {
                "attack": key,
                "description": description,
                "created_at": iso_z(utcnow()),
                "detected": 1 if detected else 0,
                "restored": 0,
                "failures_json": json.dumps(failures),
            }
        )
        return {
            "attack": key,
            "name": attack.name,
            "layer": attack.layer,
            "description": description,
            "detected": detected,
            "duration_ms": duration_ms,
            "failures": failures,
            "report": report.to_dict(),
        }

    # ---------------------------------------------------------------- attacks
    def _anchored(self) -> list[dict]:
        rows = [row for row in self.store.all_readings() if row["status"] == "anchored"]
        if not rows:
            raise ValueError("no anchored readings to attack; wait for a block to be sealed")
        return rows

    def _intact(self) -> list[dict]:
        """Anchored readings whose digest, signature and inclusion all verify."""
        blocks = {row["idx"]: Block.from_row(row) for row in self.store.all_blocks()}
        intact: list[dict] = []
        for row in self._anchored():
            block = blocks.get(row["block_index"])
            if block is None or row["digest"] not in block.digests:
                continue
            key = derive_device_key(self.settings.master_secret, row["device_id"])
            if sign_reading(key, row["digest"]) != row["signature"]:
                continue
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                continue
            if reading_digest(payload) != row["digest"]:
                continue
            intact.append(row)
        if not intact:
            raise ValueError("no intact anchored reading left; reset the demo first")
        return intact

    def _preferred(self) -> dict:
        rows = self._intact()
        excursions = [row for row in rows if row["temperature_centi_c"] > int(self.settings.max_temp_c * 100)]
        return excursions[0] if excursions else rows[-1]

    def _edit_temperature(self) -> str:
        target = self._preferred()
        payload = json.loads(target["payload_json"])
        old_temp = target["temperature_centi_c"] / 100
        new_temp_centi = 350 if target["temperature_centi_c"] > 800 else 950
        payload["temperature_centi_c"] = new_temp_centi
        self.store.mutate_reading(
            target["digest"],
            {
                "temperature_centi_c": new_temp_centi,
                "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
            },
        )
        return (
            f"Changed reading {target['digest'][:12]}… of {target['device_id']} from "
            f"{old_temp:.2f} °C to {new_temp_centi / 100:.2f} °C in the readings table; "
            "digest and signature untouched."
        )

    def _resign_edit(self) -> str:
        target = self._preferred()
        payload = json.loads(target["payload_json"])
        old_temp = target["temperature_centi_c"] / 100
        payload["temperature_centi_c"] = 350
        digest = reading_digest(payload)
        key = derive_device_key(self.settings.master_secret, target["device_id"])
        self.store.mutate_reading(
            target["digest"],
            {
                "digest": digest,
                "temperature_centi_c": 350,
                "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
                "signature": sign_reading(key, digest),
            },
        )
        return (
            f"Re-hashed and re-signed a falsified reading for {target['device_id']}: "
            f"{old_temp:.2f} °C became 3.50 °C under a brand-new valid digest {digest[:12]}…"
        )

    def _forge_reading(self) -> str:
        base = self._preferred()
        payload = json.loads(base["payload_json"])
        payload["seq"] = int(base["seq"]) + 1000
        payload["measured_at"] = iso_z(utcnow())
        payload["temperature_centi_c"] = 500
        payload["nonce"] = new_nonce()
        digest = reading_digest(payload)
        latest = self.store.latest_block()
        wrong_key = derive_device_key(self.settings.master_secret, "intruder-device")
        now = iso_z(utcnow())
        self.store.insert_reading(
            {
                "digest": digest,
                "device_id": payload["device_id"],
                "seq": payload["seq"],
                "measured_at": payload["measured_at"],
                "temperature_centi_c": payload["temperature_centi_c"],
                "humidity_milli_pct": payload["humidity_milli_pct"],
                "lat_e7": payload["lat_e7"],
                "lon_e7": payload["lon_e7"],
                "gps_fix": payload["gps_fix"],
                "firmware": payload["firmware"],
                "nonce": payload["nonce"],
                "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
                "signature": sign_reading(wrong_key, digest),
                "received_at": now,
                "anchored_at": now,
                "block_index": latest["idx"],
                "status": "anchored",
                "source": "attack",
                "latency_ms": 0.0,
                "rule_violations_json": "[]",
            }
        )
        return (
            f"Injected a forged 5.00 °C reading {digest[:12]}… for {payload['device_id']}, "
            f"marked anchored to block {latest['idx']} and signed with an unauthorised key."
        )

    def _delete_reading(self) -> str:
        target = self._preferred()
        self.store.delete_reading(target["digest"])
        return (
            f"Deleted reading {target['digest'][:12]}… of {target['device_id']} "
            f"({target['temperature_centi_c'] / 100:.2f} °C) from block {target['block_index']}."
        )

    def _rewrite_block(self) -> str:
        blocks = [row for row in self.store.all_blocks() if row["idx"] > 0]
        if not blocks:
            raise ValueError("no sealed block to rewrite yet")
        target_row = blocks[-2] if len(blocks) > 1 else blocks[-1]
        block = Block.from_row(target_row)
        if not block.digests:
            raise ValueError("target block has no readings")
        removed = block.digests.pop()
        block.merkle_root = merkle_root(block.digests)
        block.hash = block.compute_hash()
        self.store.mutate_block(
            block.index,
            {
                "hash": block.hash,
                "merkle_root": block.merkle_root,
                "digests_json": json.dumps(block.digests),
                "reading_count": len(block.digests),
            },
        )
        return (
            f"Rewrote block {block.index}: removed reading {removed[:12]}…, recomputed the "
            f"Merkle root and block hash {block.hash[:16]}… without re-mining or re-signing."
        )

    def _replay(self) -> str:
        if self.gateway is None:
            raise ValueError("gateway is not running; replay requires the MQTT ingest path")
        target = self._intact()[-1]
        envelope = {
            "alg": "HMAC-SHA256",
            "digest": target["digest"],
            "payload": json.loads(target["payload_json"]),
            "signature": target["signature"],
        }
        result = self.gateway.ingest(envelope, source="replay")
        self._last_replay_rejected = not result.accepted and result.reason == "DUPLICATE"
        return (
            f"Replayed signed reading {target['digest'][:12]}… from {target['device_id']}; "
            f"gateway verdict: {result.reason or 'accepted'}."
        )

    _last_replay_rejected: bool = False
