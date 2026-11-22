"""Immutable ledger: blocks, proof-of-work, Merkle commitments, validator quorum."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from .crypto import (
    EMPTY_MERKLE_ROOT,
    GENESIS_PARENT,
    canonical_json,
    merkle_proof,
    merkle_root,
    sha256_hex,
    sign_block,
    verify_merkle_proof,
)
from .models import iso_z, utcnow


@dataclass
class Block:
    index: int
    created_at: str
    prev_hash: str
    merkle_root: str
    digests: list[str]
    alert_digests: list[str]
    excursion_count: int
    policy: dict
    difficulty: int
    nonce: int = 0
    hash: str = ""
    validator_sigs: list[dict] = field(default_factory=list)

    def header(self) -> dict[str, Any]:
        return {
            "alert_digests": list(self.alert_digests),
            "created_at": self.created_at,
            "difficulty": self.difficulty,
            "excursion_count": self.excursion_count,
            "index": self.index,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "policy": self.policy,
            "prev_hash": self.prev_hash,
            "reading_count": len(self.digests),
            "reading_digests": list(self.digests),
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.header()))

    def mine(self, difficulty: int | None = None) -> float:
        """Increment the nonce until the hash meets the leading-zero target.

        The canonical header is assembled once; only the nonce digits change per
        attempt, which keeps difficulty-4 sealing around 100 ms in CPython.
        """
        self.difficulty = self.difficulty if difficulty is None else difficulty
        started = time.perf_counter()

        header = self.header()
        header.pop("nonce")
        base = canonical_json(header)
        marker = base.find(b'"policy":')
        if marker < 0:  # defensive: fall back to the straightforward path
            target = "0" * self.difficulty
            while True:
                candidate = self.compute_hash()
                if candidate.startswith(target):
                    self.hash = candidate
                    return (time.perf_counter() - started) * 1000
                self.nonce += 1

        prefix = base[:marker] + b'"nonce":'
        suffix = b"," + base[marker:]
        full_bytes, remainder = divmod(self.difficulty, 2)
        zero_bytes = b"\x00" * full_bytes
        hasher = hashlib.sha256

        while True:
            digest = hasher(prefix + str(self.nonce).encode("ascii") + suffix).digest()
            if digest.startswith(zero_bytes) and (remainder == 0 or digest[full_bytes] >> 4 == 0):
                self.hash = digest.hex()
                return (time.perf_counter() - started) * 1000
            self.nonce += 1

    def sign(self, validators: list[dict]) -> None:
        self.validator_sigs = [
            {"validator": v["id"], "sig": sign_block(v["key"], self.hash)} for v in validators
        ]

    def signature_report(self, validators: list[dict], quorum: int) -> tuple[int, list[str]]:
        keys = {v["id"]: v["key"] for v in validators}
        valid = 0
        invalid: list[str] = []
        seen: set[str] = set()
        for entry in self.validator_sigs:
            validator_id = entry.get("validator")
            if validator_id in seen or validator_id not in keys:
                invalid.append(str(validator_id))
                continue
            seen.add(validator_id)
            if sign_block(keys[validator_id], self.hash) == entry.get("sig"):
                valid += 1
            else:
                invalid.append(str(validator_id))
        if valid < quorum:
            return valid, invalid or ["quorum-not-met"]
        return valid, invalid

    def to_row(self, mine_ms: float = 0.0, synthetic: bool = False) -> dict:
        import json

        return {
            "idx": self.index,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "created_at": self.created_at,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "reading_count": len(self.digests),
            "digests_json": json.dumps(self.digests),
            "alert_digests_json": json.dumps(self.alert_digests),
            "excursion_count": self.excursion_count,
            "policy_json": json.dumps(self.policy, sort_keys=True),
            "validator_sigs_json": json.dumps(self.validator_sigs),
            "mine_ms": round(mine_ms, 3),
            "synthetic": 1 if synthetic else 0,
        }

    @classmethod
    def from_row(cls, row: dict) -> "Block":
        import json

        return cls(
            index=row["idx"],
            created_at=row["created_at"],
            prev_hash=row["prev_hash"],
            merkle_root=row["merkle_root"],
            digests=json.loads(row["digests_json"]),
            alert_digests=json.loads(row["alert_digests_json"]),
            excursion_count=row["excursion_count"],
            policy=json.loads(row["policy_json"]),
            difficulty=row["difficulty"],
            nonce=row["nonce"],
            hash=row["hash"],
            validator_sigs=json.loads(row["validator_sigs_json"]),
        )

    def to_public(self) -> dict:
        return {
            "index": self.index,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "created_at": self.created_at,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "reading_count": len(self.digests),
            "alert_count": len(self.alert_digests),
            "excursion_count": self.excursion_count,
            "validators": [s.get("validator") for s in self.validator_sigs],
            "policy": self.policy,
        }


@dataclass(frozen=True)
class ChainIssue:
    kind: str
    severity: str
    block_index: int | None
    detail: str
    expected: str | None = None
    actual: str | None = None

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "block_index": self.block_index,
            "detail": self.detail,
            "expected": self.expected,
            "actual": self.actual,
        }


def genesis_block(policy: dict, difficulty: int, validators: list[dict], created_at: str | None = None) -> Block:
    block = Block(
        index=0,
        created_at=created_at or iso_z(utcnow()),
        prev_hash=GENESIS_PARENT,
        merkle_root=EMPTY_MERKLE_ROOT,
        digests=[],
        alert_digests=[],
        excursion_count=0,
        policy=policy,
        difficulty=difficulty,
    )
    block.mine()
    block.sign(validators)
    return block


def validate_chain(blocks: list[dict], validators: list[dict], quorum: int) -> list[ChainIssue]:
    """Full structural verification of the persisted chain."""
    issues: list[ChainIssue] = []
    parsed = [Block.from_row(row) for row in blocks]
    if not parsed:
        return [ChainIssue("CHAIN_EMPTY", "critical", None, "no genesis block found")]

    if parsed[0].index != 0:
        issues.append(
            ChainIssue("GENESIS_MISSING", "critical", parsed[0].index, "chain does not start at index 0")
        )

    previous: Block | None = None
    for block in parsed:
        if previous is not None:
            if block.index != previous.index + 1:
                issues.append(
                    ChainIssue(
                        "BLOCK_INDEX_GAP",
                        "critical",
                        block.index,
                        f"block index {block.index} does not follow {previous.index}",
                    )
                )
            if block.prev_hash != previous.hash:
                issues.append(
                    ChainIssue(
                        "BLOCK_LINK_BROKEN",
                        "critical",
                        block.index,
                        "previous-hash link does not match the preceding block",
                        expected=previous.hash,
                        actual=block.prev_hash,
                    )
                )
        else:
            if block.prev_hash != GENESIS_PARENT:
                issues.append(
                    ChainIssue(
                        "GENESIS_PARENT_INVALID",
                        "critical",
                        block.index,
                        "genesis parent hash is not the zero hash",
                        expected=GENESIS_PARENT,
                        actual=block.prev_hash,
                    )
                )

        recomputed = block.compute_hash()
        if recomputed != block.hash:
            issues.append(
                ChainIssue(
                    "BLOCK_HASH_MISMATCH",
                    "critical",
                    block.index,
                    "block header no longer hashes to the stored block hash",
                    expected=recomputed,
                    actual=block.hash,
                )
            )
        if not block.hash.startswith("0" * block.difficulty):
            issues.append(
                ChainIssue(
                    "BLOCK_POW_INVALID",
                    "critical",
                    block.index,
                    f"block hash does not meet difficulty {block.difficulty}",
                )
            )
        if len(block.digests) != len(set(block.digests)):
            issues.append(
                ChainIssue("BLOCK_DUPLICATE_DIGEST", "critical", block.index, "block commits a duplicate reading")
            )
        expected_root = merkle_root(block.digests)
        if expected_root != block.merkle_root:
            issues.append(
                ChainIssue(
                    "BLOCK_MERKLE_MISMATCH",
                    "critical",
                    block.index,
                    "recomputed Merkle root differs from the committed root",
                    expected=expected_root,
                    actual=block.merkle_root,
                )
            )
        valid_sigs, invalid_sigs = block.signature_report(validators, quorum)
        if valid_sigs < quorum:
            issues.append(
                ChainIssue(
                    "BLOCK_QUORUM_FAILURE",
                    "critical",
                    block.index,
                    f"{valid_sigs}/{quorum} validator signatures valid ({', '.join(invalid_sigs)})",
                )
            )
        previous = block
    return issues


def build_block(
    index: int,
    prev_hash: str,
    digests: list[str],
    alert_digests: list[str],
    excursion_count: int,
    policy: dict,
    difficulty: int,
    validators: list[dict],
    created_at: str | None = None,
) -> tuple[Block, float]:
    block = Block(
        index=index,
        created_at=created_at or iso_z(utcnow()),
        prev_hash=prev_hash,
        merkle_root=merkle_root(digests),
        digests=list(digests),
        alert_digests=list(alert_digests),
        excursion_count=excursion_count,
        policy=policy,
        difficulty=difficulty,
    )
    mine_ms = block.mine()
    block.sign(validators)
    return block, mine_ms


def reading_proof(digest: str, block: Block) -> dict:
    index = block.digests.index(digest)
    proof = merkle_proof(block.digests, index)
    return {
        "digest": digest,
        "block_index": block.index,
        "block_hash": block.hash,
        "merkle_root": block.merkle_root,
        "leaf_index": index,
        "proof": proof,
        "verified": verify_merkle_proof(digest, proof, block.merkle_root),
    }
