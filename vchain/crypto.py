"""Hashing, canonical encoding, key derivation and Merkle proofs.

Every value that crosses the wire or the ledger is hashed in a canonical form:
JSON with sorted keys, no whitespace and ASCII-only escaping. That removes
serialisation ambiguity, so the ESP32 firmware and the Python gateway produce
byte-identical payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Iterable, Sequence

GENESIS_PARENT = "0" * 64
EMPTY_MERKLE_ROOT = "0" * 64

DOMAIN_READING = b"VCHAIN/reading/v1:"
DOMAIN_BLOCK = b"VCHAIN/block/v1:"
DOMAIN_DEVICE_KEY = b"VCHAIN/device-key/v1:"
DOMAIN_VALIDATOR_KEY = b"VCHAIN/validator-key/v1:"
DOMAIN_LEAF = b"\x00"
DOMAIN_NODE = b"\x01"


def canonical_json(obj: object) -> bytes:
    """Deterministic JSON encoding used for every digest in the system."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: str | bytes, message: bytes | str) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def derive_device_key(master_secret: str, device_id: str) -> str:
    return hmac_sha256_hex(master_secret, DOMAIN_DEVICE_KEY + device_id.encode("utf-8"))


def derive_validator_key(master_secret: str, index: int) -> str:
    return hmac_sha256_hex(master_secret, DOMAIN_VALIDATOR_KEY + str(index).encode("utf-8"))


def reading_digest(payload: dict) -> str:
    """SHA-256 over the canonical telemetry payload."""
    return sha256_hex(DOMAIN_READING + canonical_json(payload))


def sign_reading(device_key: str, digest: str) -> str:
    return hmac_sha256_hex(device_key, DOMAIN_READING + bytes.fromhex(digest))


def sign_block(validator_key: str, block_hash: str) -> str:
    return hmac_sha256_hex(validator_key, DOMAIN_BLOCK + bytes.fromhex(block_hash))


def merkle_leaf(digest: str) -> bytes:
    return hashlib.sha256(DOMAIN_LEAF + bytes.fromhex(digest)).digest()


def merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_NODE + left + right).digest()


def merkle_root(digests: Sequence[str]) -> str:
    """Merkle root over reading digests, duplicating the last odd node."""
    if not digests:
        return EMPTY_MERKLE_ROOT
    level = [merkle_leaf(d) for d in digests]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(digests: Sequence[str], index: int) -> list[dict]:
    """Audit path for one leaf: [{'position': 'left'|'right', 'hash': hex}]."""
    if not 0 <= index < len(digests):
        raise IndexError("leaf index out of range")
    level = [merkle_leaf(d) for d in digests]
    position = index
    proof: list[dict] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position ^ 1
        proof.append(
            {
                "position": "left" if sibling < position else "right",
                "hash": level[sibling].hex(),
            }
        )
        level = [merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return proof


def verify_merkle_proof(digest: str, proof: Iterable[dict], root: str) -> bool:
    node = merkle_leaf(digest)
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        node = merkle_parent(sibling, node) if step["position"] == "left" else merkle_parent(node, sibling)
    return node.hex() == root


def new_nonce(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)
