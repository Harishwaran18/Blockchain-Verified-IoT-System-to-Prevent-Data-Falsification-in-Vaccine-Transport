from __future__ import annotations

import hashlib

import pytest

from vchain.crypto import (
    EMPTY_MERKLE_ROOT,
    canonical_json,
    constant_time_equals,
    derive_device_key,
    derive_validator_key,
    hmac_sha256_hex,
    merkle_leaf,
    merkle_parent,
    merkle_proof,
    merkle_root,
    new_nonce,
    reading_digest,
    sha256_hex,
    sign_block,
    sign_reading,
    verify_merkle_proof,
)


def test_canonical_json_is_sorted_and_compact():
    payload = {"b": 2, "a": 1, "nested": {"z": True, "y": None}}
    assert canonical_json(payload) == b'{"a":1,"b":2,"nested":{"y":null,"z":true}}'


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_sha256_known_vector():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hmac_known_vector():
    assert (
        hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog")
        == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    )


def test_constant_time_equals():
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")


def test_key_derivation_is_deterministic_and_domain_separated():
    device = derive_device_key("master", "VX-001")
    validator = derive_validator_key("master", 1)
    assert device == derive_device_key("master", "VX-001")
    assert device != derive_device_key("master", "VX-002")
    assert validator != derive_validator_key("master", 2)
    assert len(device) == len(validator) == 64


def test_reading_digest_changes_with_every_field():
    base = {
        "device_id": "VX-001",
        "firmware": "1.0.0",
        "gps_fix": 1,
        "humidity_milli_pct": 45000,
        "lat_e7": 100,
        "lon_e7": 200,
        "measured_at": "2026-01-01T00:00:00.000Z",
        "nonce": "0011223344556677",
        "seq": 1,
        "temperature_centi_c": 500,
    }
    digest = reading_digest(base)
    assert len(digest) == 64
    for field, value in {
        "device_id": "VX-002",
        "firmware": "1.0.1",
        "gps_fix": 0,
        "humidity_milli_pct": 45001,
        "lat_e7": 101,
        "lon_e7": 201,
        "measured_at": "2026-01-01T00:00:00.001Z",
        "nonce": "0011223344556678",
        "seq": 2,
        "temperature_centi_c": 501,
    }.items():
        mutated = dict(base)
        mutated[field] = value
        assert reading_digest(mutated) != digest


def test_reading_signature_roundtrip():
    key = derive_device_key("master", "VX-001")
    digest = sha256_hex("payload")
    signature = sign_reading(key, digest)
    assert sign_reading(key, digest) == signature
    assert sign_reading(derive_device_key("master", "VX-002"), digest) != signature


def test_block_signature_uses_domain_separation():
    key = derive_validator_key("master", 1)
    digest = sha256_hex("block")
    assert sign_block(key, digest) != sign_reading(key, digest)


def test_empty_merkle_root():
    assert merkle_root([]) == EMPTY_MERKLE_ROOT


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16])
def test_merkle_proofs_verify_for_every_leaf(size):
    digests = [sha256_hex(f"leaf-{i}") for i in range(size)]
    root = merkle_root(digests)
    for index, digest in enumerate(digests):
        proof = merkle_proof(digests, index)
        assert verify_merkle_proof(digest, proof, root)
        assert not verify_merkle_proof(sha256_hex("other"), proof, root)


def test_merkle_proof_positions():
    digests = [sha256_hex(f"leaf-{i}") for i in range(4)]
    proof = merkle_proof(digests, 0)
    assert [step["position"] for step in proof] == ["right", "right"]
    proof = merkle_proof(digests, 3)
    assert [step["position"] for step in proof] == ["left", "left"]


def test_merkle_proof_rejects_out_of_range():
    with pytest.raises(IndexError):
        merkle_proof([sha256_hex("a")], 1)


def test_merkle_leaf_is_domain_separated():
    digest = sha256_hex("leaf")
    assert merkle_leaf(digest) != bytes.fromhex(digest)
    assert merkle_leaf(digest) == hashlib.sha256(b"\x00" + bytes.fromhex(digest)).digest()
    assert merkle_parent(b"a", b"b") == hashlib.sha256(b"\x01ab").digest()


def test_nonce_shape():
    nonce = new_nonce()
    assert len(nonce) == 16
    assert int(nonce, 16) >= 0
    assert new_nonce() != nonce
