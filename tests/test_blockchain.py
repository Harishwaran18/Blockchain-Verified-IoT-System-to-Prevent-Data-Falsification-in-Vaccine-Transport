from __future__ import annotations

import json

from vchain.blockchain import (
    Block,
    build_block,
    genesis_block,
    reading_proof,
    validate_chain,
)
from vchain.crypto import EMPTY_MERKLE_ROOT, canonical_json, derive_validator_key, merkle_root, sha256_hex

VALIDATORS = [
    {"id": "validator-1", "key": derive_validator_key("master", 1)},
    {"id": "validator-2", "key": derive_validator_key("master", 2)},
    {"id": "validator-3", "key": derive_validator_key("master", 3)},
]
POLICY = {"min_temp_centi_c": 200, "max_temp_centi_c": 800}


def make_chain(size: int = 3) -> list[dict]:
    rows = []
    genesis = genesis_block(POLICY, 2, VALIDATORS, created_at="2026-01-01T00:00:00.000Z")
    rows.append(genesis.to_row())
    previous = genesis
    for index in range(1, size + 1):
        digests = [sha256_hex(f"reading-{index}-{i}") for i in range(4)]
        block, mine_ms = build_block(
            index=index,
            prev_hash=previous.hash,
            digests=digests,
            alert_digests=[],
            excursion_count=0,
            policy=POLICY,
            difficulty=2,
            validators=VALIDATORS,
            created_at=f"2026-01-01T00:0{index}:00.000Z",
        )
        rows.append(block.to_row(mine_ms=mine_ms))
        previous = block
    return rows


def test_genesis_block_shape():
    genesis = genesis_block(POLICY, 2, VALIDATORS)
    assert genesis.index == 0
    assert genesis.prev_hash == "0" * 64
    assert genesis.merkle_root == EMPTY_MERKLE_ROOT
    assert genesis.digests == []
    assert genesis.hash.startswith("00")
    assert genesis.hash == genesis.compute_hash()
    assert len(genesis.validator_sigs) == 3


def test_mining_matches_canonical_hash_for_all_difficulties():
    for difficulty in range(0, 5):
        block = Block(
            index=1,
            created_at="2026-01-01T00:00:00.000Z",
            prev_hash="a" * 64,
            merkle_root=EMPTY_MERKLE_ROOT,
            digests=[sha256_hex("x"), sha256_hex("y")],
            alert_digests=[],
            excursion_count=0,
            policy=POLICY,
            difficulty=difficulty,
        )
        block.mine()
        assert block.hash == sha256_hex(canonical_json(block.header()))
        assert block.hash.startswith("0" * difficulty)


def test_chain_validates_clean():
    issues = validate_chain(make_chain(), VALIDATORS, quorum=2)
    assert issues == []


def test_tampered_digest_breaks_merkle_and_hash():
    rows = make_chain()
    block = Block.from_row(rows[2])
    block.digests[0] = sha256_hex("forged")
    rows[2] = block.to_row()
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_MERKLE_MISMATCH" in kinds
    assert "BLOCK_HASH_MISMATCH" in kinds


def test_tampered_block_hash_is_detected():
    rows = make_chain()
    rows[1]["hash"] = "f" * 64
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_HASH_MISMATCH" in kinds


def test_broken_link_is_detected():
    rows = make_chain()
    rows[2]["prev_hash"] = "b" * 64
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_LINK_BROKEN" in kinds


def test_pow_violation_is_detected():
    rows = make_chain()
    rows[1]["hash"] = "f" * 64
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_POW_INVALID" in kinds
    assert "BLOCK_LINK_BROKEN" in kinds  # child still points at the old hash


def test_validator_signature_tampering_is_detected():
    rows = make_chain()
    row = rows[1]
    signatures = json.loads(row["validator_sigs_json"])
    signatures[0]["sig"] = "0" * 64
    signatures[1]["sig"] = "0" * 64
    row["validator_sigs_json"] = json.dumps(signatures)
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_QUORUM_FAILURE" in kinds


def test_missing_genesis_and_gap():
    rows = make_chain()
    assert validate_chain([], VALIDATORS, 2)[0].kind == "CHAIN_EMPTY"
    kinds = {issue.kind for issue in validate_chain(rows[1:], VALIDATORS, 2)}
    assert "GENESIS_MISSING" in kinds
    kinds = {issue.kind for issue in validate_chain([rows[0], rows[2]], VALIDATORS, 2)}
    assert "BLOCK_INDEX_GAP" in kinds


def test_reading_proof():
    rows = make_chain()
    block = Block.from_row(rows[1])
    proof = reading_proof(block.digests[2], block)
    assert proof["verified"]
    assert proof["leaf_index"] == 2
    assert proof["merkle_root"] == block.merkle_root


def test_duplicate_digest_in_block_is_detected():
    rows = make_chain()
    block = Block.from_row(rows[1])
    block.digests[1] = block.digests[0]
    block.merkle_root = merkle_root(block.digests)
    block.hash = block.compute_hash()
    rows[1] = block.to_row()
    kinds = {issue.kind for issue in validate_chain(rows, VALIDATORS, 2)}
    assert "BLOCK_DUPLICATE_DIGEST" in kinds
