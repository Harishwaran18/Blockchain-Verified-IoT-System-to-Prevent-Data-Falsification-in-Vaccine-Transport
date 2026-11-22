# AGENTS.md

Repository-specific guidance for OpenHands and other coding agents.

## What this project is

VChain is a runnable reference implementation of a blockchain-verified IoT
cold-chain system for vaccine transport: ESP32 firmware, MQTT gateway, Merkle
rooted proof-of-work ledger with a validator quorum, independent audit engine,
tamper lab, FastAPI dashboard, and a Solidity anchoring contract.

The Python ledger is the executable reference. The Solidity contract is a
deployment target that mirrors the commitments; it is not compiled in CI.

## Commands

```bash
# install
pip install -r requirements.txt

# run the demo (embedded broker + 4 simulated nodes + dashboard)
PYTHONPATH=. python -m vchain --port 12000 --fresh

# tests (109)
PYTHONPATH=. pytest -q

# benchmark; rewrites docs/BENCHMARK.md and docs/benchmark.json, fails if a claim fails
PYTHONPATH=. python scripts/benchmark.py

# C++/Python canonical encoder parity
g++ -std=c++17 firmware/test/test_canonical.cpp -o /tmp/canonical && /tmp/canonical

# derive an ESP32 device key
VCHAIN_MASTER_SECRET=... python scripts/provision_device.py VX-001
```

The app needs no external broker or database. `amqtt` provides the embedded
broker. Tests allocate random MQTT ports; never hardcode 1883 in tests.

## Layout

- `vchain/crypto.py` — canonical JSON, SHA-256, HMAC, Merkle root/proofs, key derivation.
- `vchain/models.py` — strict fixed-point payload and envelope validation.
- `vchain/policy.py` — cold-chain rules; mirrors the contract.
- `vchain/blockchain.py` — `Block`, optimized PoW, validator signatures, chain validation.
- `vchain/store.py` — SQLite schema and all persistence; `revision` invalidates caches.
- `vchain/gateway.py` — MQTT ingest, verification, batching, anchoring.
- `vchain/audit.py` — independent full verification. This is the source of truth.
- `vchain/tamper.py` — six destructive attacks. They intentionally corrupt state.
- `vchain/runtime.py` — composition root, seeding, reset, snapshots.
- `vchain/api.py` + `vchain/web/` — API and dashboard.
- `firmware/vaccine_node/` — ESP32 sketch and canonical encoder.
- `contracts/VaccineLedger.sol` — on-chain anchor, proofs, attestations.
- `docs/` — architecture, threat model, API, generated benchmark.

## Invariants and gotchas

1. **Fixed-point telemetry only.** Sensor values are integers (`*_centi_c`,
   `*_milli_pct`, `*_e7`). Never introduce floats into the signed payload; Python
   and C++ float formatting will diverge and break every digest.
2. **Canonical JSON is a wire contract.** `canonical_json()` (sorted keys, no
   spaces, ASCII, `allow_nan=False`) must match `firmware/vaccine_node/canonical.h`.
   Run `tests/test_canonical_parity.py` after touching either side.
3. **Domain separation matters.** Reading digests/signatures use
   `VCHAIN/reading/v1:`; block signatures use `VCHAIN/block/v1:`; Merkle leaves
   use `0x00`, nodes use `0x01`. Do not reuse a domain.
4. **Adding a payload field** requires changes in `models.PAYLOAD_FIELDS`,
   validation, `canonical.h`, the C++ test fixture, `gateway._reading_row`,
   `runtime._reading_public`, the SQLite schema, and docs.
5. **`store.revision`** must increment on any mutation that can affect cached
   chain validation. `runtime.chain_issues()` caches by revision.
6. **Tamper lab is destructive by design.** Do not "fix" an attack by restoring
   rows; the UI keeps corruption visible until `POST /api/reset`.
7. **Latency definition.** `latency_ms = anchored_at − received_at` (MQTT
   receipt → sealed block). `source='seed'` and `source='replay'` are excluded
   from latency statistics. The benchmark measures fast full batches; the live
   dashboard measures a 2 s node cadence with a 1 s maximum batch wait. Both
   must stay under 1.8 s.
8. **Reset semantics.** `runtime.reset()` drops all tables, recreates genesis,
   resets node sequence counters, and re-seeds only when `settings.seed_demo`.
9. **Rejections are evidence.** Rejected readings are stored with
   `status='rejected'`; the audit verifies that they genuinely fail digest or
   signature checks (`REJECTED_BUT_VALID` otherwise).
10. **Block header commits the digest list**, not only the Merkle root, so row
    deletion is detectable. Keep `reading_digests` in the header.
11. **No secrets in git.** `firmware/vaccine_node/secrets.h`, `.env`, `.data/`
    and `*.db` are ignored. Never log `VCHAIN_MASTER_SECRET`.

## Testing guidance

- Unit tests live beside the module they cover (`tests/test_*.py`).
- Integration tests use the real embedded broker and real paho clients; do not
  mock the MQTT path. The gateway, store, audit and tamper tests exercise real
  code.
- Use `conftest.wait_until` for asynchronous anchoring assertions.
- Parametrized audit tests create a fresh runtime per attack to keep findings
  isolated.
- If you add an endpoint, add it to `tests/test_api.py` and `docs/API.md`.
- If you change the battery model, update `docs/BENCHMARK.md` by rerunning the
  benchmark and keep the >72 h claim true.

## Code style

- Python 3.11+, type hints on public functions, dataclasses for models.
- Keep comments for non-obvious invariants only; do not narrate changes.
- UI is dependency-free vanilla JS and canvas; no CDN or build step.
- Keep the dashboard accessible: buttons have titles/labels, hashes are
  truncated with the full value available in the detail modal.

## Demo environment

- Dashboard: port 12000 (work host 1 maps to 12000).
- MQTT broker: 127.0.0.1:1883 by default, embedded.
- Second work host maps to 12001 if a second service is needed.
- Start with `--fresh` when demo data or tamper evidence should be cleared.

## Known limitations

- HMAC shared secrets (demo) rather than per-device asymmetric keys.
- Single-node SQLite ledger; no replication or external timestamp anchor.
- Proof-of-work difficulty 4 is a demo seal, not a Sybil-resistant consensus.
- Sensors are simulated in the Python demo; firmware targets real hardware.
- No authentication on the HTTP API in demo mode.
