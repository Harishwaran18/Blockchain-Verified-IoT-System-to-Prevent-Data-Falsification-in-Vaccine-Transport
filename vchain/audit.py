"""Independent audit engine.

An auditor re-derives every digest, signature, Merkle root, block hash, proof-of-
work target and validator signature from first principles. Nothing stored by the
gateway is trusted.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime

from .blockchain import Block, ChainIssue, validate_chain
from .config import Settings
from .crypto import (
    canonical_json,
    derive_device_key,
    merkle_proof,
    reading_digest,
    sha256_hex,
    sign_reading,
    verify_merkle_proof,
)
from .models import PAYLOAD_FIELDS, iso_z, parse_iso, utcnow
from .policy import ColdChainPolicy
from .store import ChainStore


@dataclass
class AuditReport:
    started_at: str
    finished_at: str
    ok: bool
    checks: int
    readings_checked: int
    blocks_checked: int
    alerts_checked: int
    duration_ms: float
    failures: list[dict] = field(default_factory=list)
    id: int | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ok": self.ok,
            "checks": self.checks,
            "readings_checked": self.readings_checked,
            "blocks_checked": self.blocks_checked,
            "alerts_checked": self.alerts_checked,
            "duration_ms": self.duration_ms,
            "failure_count": len(self.failures),
            "failures": self.failures,
        }


class AuditEngine:
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

    def run(self, persist: bool = True) -> AuditReport:
        started_at = iso_z(utcnow())
        started = time.perf_counter()
        failures: list[ChainIssue] = []
        checks = 0

        block_rows = self.store.all_blocks()
        blocks = [Block.from_row(row) for row in block_rows]
        by_index = {block.index: block for block in blocks}
        checks += 1
        failures.extend(validate_chain(block_rows, self.validators, self.quorum))
        checks += len(blocks) * 6

        committed: dict[str, tuple[Block, int]] = {}
        for block in blocks:
            for index, digest in enumerate(block.digests):
                committed[digest] = (block, index)

        readings = self.store.all_readings()
        reading_digests: set[str] = set()
        now = utcnow()

        for row in readings:
            reading_digests.add(row["digest"])
            checks += 1
            if row["status"] == "rejected":
                self._audit_rejection(row, failures)
                continue

            payload = self._payload(row, failures)
            if payload is not None:
                if reading_digest(payload) != row["digest"]:
                    failures.append(
                        ChainIssue(
                            "READING_DIGEST_MISMATCH",
                            "critical",
                            row["block_index"],
                            f"reading {row['digest'][:12]}… no longer hashes to its stored digest",
                            expected=reading_digest(payload),
                            actual=row["digest"],
                        )
                    )
                for field_name in PAYLOAD_FIELDS:
                    if field_name in payload and payload[field_name] != row[field_name]:
                        failures.append(
                            ChainIssue(
                                "READING_FIELD_MISMATCH",
                                "critical",
                                row["block_index"],
                                f"stored column {field_name} disagrees with the signed payload",
                                expected=str(payload[field_name]),
                                actual=str(row[field_name]),
                            )
                        )

            key = derive_device_key(self.settings.master_secret, row["device_id"])
            if sign_reading(key, row["digest"]) != row["signature"]:
                failures.append(
                    ChainIssue(
                        "READING_SIGNATURE_INVALID",
                        "critical",
                        row["block_index"],
                        f"reading {row['digest'][:12]}… is not signed by {row['device_id']}",
                    )
                )

            if row["status"] == "anchored":
                block = by_index.get(row["block_index"]) if row["block_index"] is not None else None
                if block is None:
                    failures.append(
                        ChainIssue(
                            "READING_UNANCHORED",
                            "critical",
                            row["block_index"],
                            f"reading {row['digest'][:12]}… claims an unknown block",
                        )
                    )
                elif row["digest"] not in block.digests:
                    failures.append(
                        ChainIssue(
                            "READING_NOT_IN_BLOCK",
                            "critical",
                            block.index,
                            f"reading {row['digest'][:12]}… is not committed by block {block.index}",
                        )
                    )
                else:
                    leaf_index = block.digests.index(row["digest"])
                    proof = merkle_proof(block.digests, leaf_index)
                    checks += len(proof) + 1
                    if not verify_merkle_proof(row["digest"], proof, block.merkle_root):
                        failures.append(
                            ChainIssue(
                                "READING_PROOF_INVALID",
                                "critical",
                                block.index,
                                f"Merkle inclusion proof failed for {row['digest'][:12]}…",
                            )
                        )
            elif row["status"] == "pending":
                age = (now - parse_iso(row["received_at"])).total_seconds()
                if age > self.settings.pending_timeout_s:
                    failures.append(
                        ChainIssue(
                            "READING_PENDING_TOO_LONG",
                            "warning",
                            None,
                            f"reading {row['digest'][:12]}… has been pending for {age:.0f}s",
                        )
                    )
            else:
                failures.append(
                    ChainIssue(
                        "READING_STATUS_INVALID",
                        "critical",
                        row["block_index"],
                        f"unknown reading status {row['status']!r}",
                    )
                )

        for digest, (block, _) in committed.items():
            checks += 1
            if digest not in reading_digests:
                failures.append(
                    ChainIssue(
                        "ANCHORED_READING_MISSING",
                        "critical",
                        block.index,
                        f"block {block.index} commits {digest[:12]}… but the reading row is gone",
                    )
                )

        alerts = self.store.all_alerts()
        alert_digests = set()
        for alert in alerts:
            checks += 2
            alert_digests.add(alert["alert_digest"])
            core = {
                "created_at": alert["created_at"],
                "device_id": alert["device_id"],
                "kind": alert["kind"],
                "message": alert["message"],
                "reading_digest": alert["reading_digest"],
                "severity": alert["severity"],
            }
            if sha256_hex(canonical_json(core)) != alert["alert_digest"]:
                failures.append(
                    ChainIssue(
                        "ALERT_DIGEST_MISMATCH",
                        "critical",
                        alert["block_index"],
                        f"alert {alert['id']} fields were modified after creation",
                    )
                )
            if alert["block_index"] is not None:
                block = by_index.get(alert["block_index"])
                if block is None or alert["alert_digest"] not in block.alert_digests:
                    failures.append(
                        ChainIssue(
                            "ALERT_NOT_COMMITTED",
                            "critical",
                            alert["block_index"],
                            f"alert {alert['id']} claims block {alert['block_index']} but is not committed there",
                        )
                    )

        for block in blocks:
            for digest in block.alert_digests:
                checks += 1
                if digest not in alert_digests:
                    failures.append(
                        ChainIssue(
                            "COMMITTED_ALERT_MISSING",
                            "critical",
                            block.index,
                            f"block {block.index} commits alert {digest[:12]}… which no longer exists",
                        )
                    )

        finished_at = iso_z(utcnow())
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        report = AuditReport(
            started_at=started_at,
            finished_at=finished_at,
            ok=not failures,
            checks=checks,
            readings_checked=len(readings),
            blocks_checked=len(blocks),
            alerts_checked=len(alerts),
            duration_ms=duration_ms,
            failures=[issue.to_dict() for issue in failures],
        )
        if persist:
            report.id = self.store.insert_audit(
                {
                    "started_at": report.started_at,
                    "finished_at": report.finished_at,
                    "ok": 1 if report.ok else 0,
                    "checks": report.checks,
                    "readings_checked": report.readings_checked,
                    "blocks_checked": report.blocks_checked,
                    "alerts_checked": report.alerts_checked,
                    "duration_ms": report.duration_ms,
                    "failures_json": json.dumps(report.failures),
                }
            )
        return report

    def latest(self) -> dict | None:
        row = self.store.latest_audit()
        if row is None:
            return None
        return {
            "id": row["id"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "ok": bool(row["ok"]),
            "checks": row["checks"],
            "readings_checked": row["readings_checked"],
            "blocks_checked": row["blocks_checked"],
            "alerts_checked": row["alerts_checked"],
            "duration_ms": row["duration_ms"],
            "failure_count": len(json.loads(row["failures_json"])),
            "failures": json.loads(row["failures_json"]),
        }

    def _payload(self, row: dict, failures: list[ChainIssue]) -> dict | None:
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            failures.append(
                ChainIssue(
                    "READING_PAYLOAD_CORRUPT",
                    "critical",
                    row["block_index"],
                    f"reading {row['digest'][:12]}… has invalid JSON payload",
                )
            )
            return None
        if not isinstance(payload, dict):
            failures.append(
                ChainIssue(
                    "READING_PAYLOAD_CORRUPT",
                    "critical",
                    row["block_index"],
                    f"reading {row['digest'][:12]}… payload is not an object",
                )
            )
            return None
        return payload

    def _audit_rejection(self, row: dict, failures: list[ChainIssue]) -> None:
        """A rejected reading must genuinely fail digest or signature checks."""
        try:
            payload = json.loads(row["payload_json"])
            digest_ok = isinstance(payload, dict) and reading_digest(payload) == row["digest"]
        except json.JSONDecodeError:
            digest_ok = False
        key = derive_device_key(self.settings.master_secret, row["device_id"])
        signature_ok = sign_reading(key, row["digest"]) == row["signature"]
        if digest_ok and signature_ok:
            failures.append(
                ChainIssue(
                    "REJECTED_BUT_VALID",
                    "critical",
                    None,
                    f"reading {row['digest'][:12]}… was rejected even though it verifies",
                )
            )
