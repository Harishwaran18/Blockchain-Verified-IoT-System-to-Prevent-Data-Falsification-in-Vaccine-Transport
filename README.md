# VChain

**Blockchain-verified IoT system to prevent data falsification in vaccine transport.**

VChain makes cold-chain telemetry tamper-evident end to end. An ESP32 node
hashes and signs every temperature/humidity/GPS sample at the edge. A gateway
verifies the signature, applies cold-chain policy, batches readings, and anchors
a Merkle root into a proof-of-work block signed by three validators. An
independent audit engine re-derives every hash, signature, Merkle proof and
proof-of-work target from scratch — so an insider who edits the database cannot
hide the edit.

The repository contains a complete, runnable system: ESP32 firmware, an embedded
MQTT broker, the gateway and ledger, a FastAPI backend, a live dashboard, an
adversarial tamper lab, a Solidity anchoring contract, tests, and a benchmark
that verifies the project's claims.

---

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Starts the embedded MQTT broker, 4 simulated nodes, the ledger and the dashboard.
python -m vchain --port 12000 --fresh
```

Open <http://localhost:12000>.

No external broker, database or blockchain node is required for the demo. The
first launch seeds 56 backdated readings across four devices, including a
9.4 °C excursion on `VX-002`, then live nodes publish every two seconds.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--fresh` | delete the existing SQLite ledger before starting |
| `--no-nodes` | keep the dashboard but stop simulated publishers |
| `--no-seed` | start from an empty ledger (genesis only) |
| `--no-broker` | connect to an external MQTT broker instead of the embedded one |
| `--mqtt-port 1884` | change the embedded broker port |
| `--port 12001` | change the HTTP port |

### 60-second tour

1. **Live cold chain** — four nodes, safe band 2–8 °C, excursion points in red.
2. **Run audit** — the panel reports every check, reading and block re-verified.
3. **Force excursion** on a fleet row — a 9.4 °C breach appears, is anchored, and
   raises a critical alert committed into the block header.
4. **Tamper lab** — attack the database or the wire. Each attack opens a report
   showing the exact integrity failure the audit found.
5. **Export** — download the full audit bundle (blocks, readings, alerts, tamper
   history) as JSON.
6. **Reset demo** — rebuild from genesis and clear the evidence.

---

## Measured results

`python scripts/benchmark.py` drives the real MQTT path with difficulty-4
proof-of-work, 8-reading blocks and a 3-validator quorum. Latest run in this
container:

| Claim | Result | Target | Status |
| --- | --- | --- | --- |
| Anchoring latency (p95) | **38.4 ms** | < 1,800 ms | pass |
| Tamper detection | **6 / 6 attacks** | 100 % | pass |
| Field battery life | **132.5 h** | > 72 h | pass |
| Throughput | **75 readings/s** | — | — |
| Readings anchored | **240 / 240** | 100 % | pass |
| Chain structural validation | **valid** | valid | pass |

The benchmark publishes fast, so blocks fill immediately. In the live dashboard
the four nodes publish every 2 s and the gateway seals partial batches at most
1 s after receipt, which puts p95 latency at roughly **1.1–1.2 s** — still under
the 1.8 s claim. Full numbers, including per-attack findings, are in
[`docs/BENCHMARK.md`](docs/BENCHMARK.md) and
[`docs/benchmark.json`](docs/benchmark.json).

---

## Architecture

```text
┌─────────────────────────────┐
│ ESP32 vaccine node          │
│ DHT22 · NEO-6M GPS          │
│ fixed-point payload         │
│ SHA-256 + HMAC-SHA256       │
└──────────────┬──────────────┘
               │ MQTT QoS 1 (TLS in production)
               ▼
┌─────────────────────────────┐        ┌──────────────────────────────┐
│ Gateway                     │        │ Cold-chain policy engine     │
│ schema + digest + signature │───────▶│ 2–8 °C, humidity, sequence,  │
│ replay / sequence checks    │        │ timestamp skew, GPS validity │
└──────────────┬──────────────┘        └──────────────┬───────────────┘
               │ verified readings                     │ alerts
               ▼                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Batcher → Merkle root → difficulty-4 block → 3 validator signatures │
│ SQLite ledger: blocks, readings, alerts, audits, tamper events      │
└──────────────┬──────────────────────────────────────────────────────┘
               │
      ┌────────┴─────────┐
      ▼                  ▼
┌──────────────┐   ┌─────────────────────────────┐
│ FastAPI +    │   │ Independent audit engine    │
│ live dashboard│  │ re-hashes everything        │
└──────────────┘   └─────────────────────────────┘
```

The Python ledger is the executable reference implementation. The Solidity
contract in [`contracts/VaccineLedger.sol`](contracts/VaccineLedger.sol) mirrors
the same commitments on a permissioned EVM chain: Merkle roots, validator
attestations, inclusion proofs and excursion records.

### What is committed where

- **On-chain / in-block:** block header, Merkle root of reading digests, list of
  committed digests, alert digests, policy version, nonce, difficulty, validator
  signatures.
- **Off-chain:** the full sensor payload and signature, indexed by digest in
  SQLite. Anyone can recompute the digest and prove inclusion.

### Canonical, language-independent encoding

Sensor values are fixed-point integers (`temperature_centi_c`,
`humidity_milli_pct`, `lat_e7`, `lon_e7`) and JSON keys are sorted with no
whitespace. That removes float-formatting differences between the ESP32 and
Python. The firmware's `canonical.h` and Python's `canonical_json()` are tested
for byte equality.

```text
digest    = SHA-256("VCHAIN/reading/v1:" ‖ canonical_payload)
signature = HMAC-SHA256(device_key, "VCHAIN/reading/v1:" ‖ digest_bytes)
leaf      = SHA-256(0x00 ‖ digest)
node      = SHA-256(0x01 ‖ left ‖ right)
```

Domain separation prevents a reading signature from being reused as a block
signature, and prevents a raw digest from being interpreted as a Merkle leaf.

---

## What the audit catches

| Attack | Where it happens | Detection |
| --- | --- | --- |
| Naive temperature edit | SQLite row | payload digest mismatch |
| Re-hashed and re-signed edit | SQLite + stolen device key | committed digest missing from the block |
| Forged anchored reading | SQLite injection | invalid signature + not in the Merkle root |
| Evidence deletion | SQLite row deletion | block commits a digest whose row is gone |
| Ledger rewrite | block table | proof-of-work failure, broken hash link, lost validator quorum |
| Signed replay | MQTT wire | duplicate digest rejected before anchoring |

The audit also re-verifies every alert digest, every Merkle inclusion proof and
the validator quorum. Detection is 6/6 in the benchmark and in the pytest suite.

---

## Configuration

Environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Purpose |
| --- | --- | --- |
| `VCHAIN_MASTER_SECRET` | demo value | derives per-device and validator keys |
| `VCHAIN_DB_PATH` | `.data/vchain.db` | SQLite ledger |
| `VCHAIN_MQTT_HOST` / `VCHAIN_MQTT_PORT` | `127.0.0.1` / `1883` | broker |
| `VCHAIN_API_PORT` | `12000` | dashboard |
| `VCHAIN_BLOCK_SIZE` | `8` | readings per block |
| `VCHAIN_BLOCK_INTERVAL_S` | `1.0` | maximum batching wait |
| `VCHAIN_DIFFICULTY` | `4` | proof-of-work leading hex zeros |
| `VCHAIN_VALIDATORS` / `VCHAIN_QUORUM` | `3` / `2` | validator set |
| `VCHAIN_SEED_DEMO` | `1` | seed backdated demo readings |
| `VCHAIN_START_NODES` | `1` | run simulated publishers |

**Change `VCHAIN_MASTER_SECRET` before using anything outside a demo.** Per-device
keys should be provisioned into secure storage; see
`scripts/provision_device.py` and [`firmware/README.md`](firmware/README.md).

---

## Testing

```bash
PYTHONPATH=. pytest -q          # 109 tests
python scripts/benchmark.py     # regenerates docs/BENCHMARK.md and checks claims
g++ -std=c++17 firmware/test/test_canonical.cpp -o /tmp/canonical && /tmp/canonical
```

The suite covers hashing and Merkle proofs, strict payload validation, policy
rules, block mining and chain validation, real MQTT ingest, replay/forgery
rejection, every tamper attack, reset, all API endpoints, the battery model and
C++/Python canonical-encoding parity.

---

## Repository layout

```text
vchain/                 Python package
  crypto.py             canonical JSON, SHA-256, HMAC, Merkle proofs
  models.py             strict fixed-point telemetry and envelope models
  policy.py             cold-chain rule engine (mirrors the contract)
  blockchain.py         blocks, PoW, Merkle commitments, validator quorum
  store.py              SQLite ledger and audit/tamper tables
  gateway.py            MQTT ingest, verification, batching
  audit.py              independent full-ledger verification
  tamper.py             six adversarial attacks
  runtime.py            composition root, seeding, snapshots
  api.py                FastAPI service
  web/                  dashboard (HTML/CSS/JS, no CDN)
firmware/               ESP32 sketch, canonical encoder, host parity test
contracts/              Solidity anchoring contract
scripts/                benchmark, device provisioning, smoke test
tests/                  pytest suite
docs/                   architecture, threat model, API, benchmark
```

---

## Security and limitations

VChain makes **retroactive modification** detectable, not impossible at the
source. A compromised sensor can report a false temperature before it is signed;
a stolen device key can produce a valid reading for that device; and a majority
of colluding validators could finalise a false history. The demo also uses HMAC
shared secrets, an unencrypted local broker and a single SQLite node.

The production path is documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md):
TLS with certificate pinning, per-device keys in an ATECC608A or NVS encryption,
asymmetric signatures (Ed25519/ECDSA), replicated ledger nodes, an external
timestamp anchor, and the Solidity contract on a permissioned chain.

Further reading:

- [Architecture and data flow](docs/ARCHITECTURE.md)
- [Threat model and residual risks](docs/THREAT_MODEL.md)
- [HTTP API](docs/API.md)
- [Benchmark method and results](docs/BENCHMARK.md)
- [Firmware wiring and provisioning](firmware/README.md)
- [Smart contract notes](contracts/README.md)
