# Architecture

VChain separates **evidence creation** at the edge from **evidence aggregation**
at the gateway and **evidence verification** in the audit engine. No component is
trusted to report its own correctness; the audit re-derives everything from the
bytes it is given.

## Components

| Component | File | Responsibility |
| --- | --- | --- |
| Edge node | `firmware/vaccine_node/vaccine_node.ino`, `vchain/node.py` | sample sensors, canonicalise, SHA-256, HMAC, publish, deep sleep |
| Embedded broker | `vchain/mqtt_broker.py` | MQTT 3.1.1 broker for the demo (amqtt) |
| Gateway | `vchain/gateway.py` | schema check, digest/signature verification, replay and sequence checks, policy evaluation, batching, anchoring |
| Policy engine | `vchain/policy.py` | 2–8 °C band, humidity, sequence, timestamp skew, GPS validity |
| Ledger | `vchain/blockchain.py` | block headers, Merkle roots, proof-of-work, validator signatures, chain validation |
| Store | `vchain/store.py` | SQLite tables for blocks, readings, alerts, audits, tamper events |
| Audit engine | `vchain/audit.py` | independent re-derivation of every commitment |
| Tamper lab | `vchain/tamper.py` | six realistic falsification attempts |
| Runtime | `vchain/runtime.py` | composition root, demo seeding, snapshots |
| API / dashboard | `vchain/api.py`, `vchain/web/` | REST, static UI, export bundle |

## End-to-end sequence

```text
ESP32                    Broker                 Gateway                   Ledger
  │  read DHT22 + GPS       │                       │                        │
  │  canonical payload      │                       │                        │
  │  digest = SHA-256(...)  │                       │                        │
  │  sig = HMAC(key, ...)   │                       │                        │
  ├──── PUBLISH QoS 1 ─────▶│                       │                        │
  │                         ├──── deliver ─────────▶│                        │
  │                         │                       │ 1. schema validation   │
  │                         │                       │ 2. digest recompute    │
  │                         │                       │ 3. HMAC verify         │
  │                         │                       │ 4. duplicate/sequence  │
  │                         │                       │ 5. policy evaluation   │
  │                         │                       │ 6. store pending row   │
  │                         │                       │ 7. alerts (if any)     │
  │                         │                       │                        │
  │                         │             batch full or 1 s elapsed           │
  │                         │                       │ 8. Merkle root         │
  │                         │                       │ 9. PoW + 3 signatures  │
  │                         │                       ├── insert block ───────▶│
  │                         │                       │ 10. mark anchored      │
  │                         │                       │ 11. commit alerts      │
  │                         │                       │                        │
  │                         │                       │ 12. latency = anchored │
  │                         │                       │     − received         │
```

## Telemetry envelope

Payload fields are fixed-point integers so that C++ and Python encoders agree
byte for byte:

| Field | Type | Meaning |
| --- | --- | --- |
| `device_id` | string | `[A-Za-z0-9_-]{2,32}` |
| `firmware` | string | `[0-9A-Za-z._-]{1,20}` |
| `gps_fix` | 0/1 | GPS lock state |
| `humidity_milli_pct` | int | %RH × 1000 |
| `lat_e7` | int | degrees × 1e7 |
| `lon_e7` | int | degrees × 1e7 |
| `measured_at` | string | UTC `YYYY-MM-DDTHH:MM:SS.mmmZ` |
| `nonce` | string | 8–64 lowercase hex |
| `seq` | int | monotonic per device |
| `temperature_centi_c` | int | °C × 100 |

Canonical encoding is JSON with sorted keys, `,`/`:` separators, ASCII escaping
and no whitespace. The envelope adds `alg`, `digest` and `signature` (sorted
keys). The digest covers the domain prefix `VCHAIN/reading/v1:` and the canonical
payload; the signature covers the same prefix and the raw 32 digest bytes.

## Block specification

```json
{
  "alert_digests": ["<sha256 of alert core>"],
  "created_at": "2026-11-22T09:34:51.000Z",
  "difficulty": 4,
  "excursion_count": 3,
  "index": 12,
  "merkle_root": "<64 hex>",
  "nonce": 271828,
  "policy": {
    "humidity_max_milli_pct": 80000,
    "humidity_min_milli_pct": 20000,
    "max_future_skew_s": 300,
    "max_gap_s": 900,
    "max_past_skew_s": 86400,
    "max_temp_centi_c": 800,
    "min_temp_centi_c": 200
  },
  "prev_hash": "<64 hex>",
  "reading_count": 8,
  "reading_digests": ["<64 hex>", "..."]
}
```

- `block_hash = SHA-256(canonical_json(header))`
- Proof-of-work: `block_hash` starts with `difficulty` hex zeros (default 4).
- Genesis: index 0, `prev_hash` all zeros, empty Merkle root (`"00" * 32`).
- Validator signature: `HMAC-SHA256(validator_key, "VCHAIN/block/v1:" ‖ block_hash_bytes)`.
- Quorum: at least `quorum` distinct valid signatures over the block hash.
- The policy dict is committed, so the rules that judged a batch cannot be
  retroactively changed.

The list of committed digests is included in the header (not only the Merkle
root) so that deletion of a reading row is detectable even when the Merkle root
still verifies.

## Merkle tree

- Leaves are reading digests: `leaf = SHA-256(0x00 ‖ digest_bytes)`.
- Internal nodes: `node = SHA-256(0x01 ‖ left ‖ right)`.
- Odd levels duplicate the last node before pairing.
- Proofs are sibling lists with `left`/`right` positions; verification is
  O(log n) and is exercised for every anchored reading by the audit.
- Alert digests are committed as a flat list in the header, and each alert's
  digest is recomputed from its fields during audit.

## Policy engine

Rules run on the gateway before a reading is accepted and are re-evaluated for
alerts only at ingest time; the audit verifies that the committed alert set
matches the stored alerts.

| Rule | Severity | Action |
| --- | --- | --- |
| `TEMPERATURE_HIGH` / `TEMPERATURE_LOW` | critical | anchor + alert |
| `HUMIDITY_OUT_OF_RANGE` | warning | anchor + alert |
| `SEQUENCE_REPLAY` | critical | reject, alert, never anchor |
| `SEQUENCE_GAP` | warning | anchor + alert |
| `TIMESTAMP_FUTURE` / `TIMESTAMP_STALE` | warning | anchor + alert |
| `GPS_NO_FIX` | info | anchor + alert |
| `GPS_NULL_ISLAND` | warning | anchor + alert |
| `DUPLICATE_REPLAY` | warning | reject, deduplicated alert |
| `SIGNATURE_INVALID` / `DIGEST_MISMATCH` | critical | reject, alert |

Rejected readings are stored with `status='rejected'` so the audit can verify
that they genuinely fail digest or signature checks. A rejected reading that
actually verifies raises `REJECTED_BUT_VALID`.

## Persistence

SQLite in WAL mode, one connection per runtime, guarded by an `RLock`:

| Table | Purpose |
| --- | --- |
| `blocks` | header fields, digests JSON, alert digests JSON, validator signatures, seal time |
| `readings` | payload JSON, signature, status, block index, latency, rule violations |
| `alerts` | alert core + digest + committed block index |
| `device_state` | last accepted sequence per device |
| `audit_runs` | every audit result and its failures |
| `tamper_events` | attack, description, detected flag, findings |
| `meta` | genesis hash and small key/value state |

`ChainStore.revision` increments on every mutation and invalidates the runtime's
chain-validation cache, so a tampered block is reflected immediately in the UI.

## Concurrency

- The embedded broker runs its own asyncio event loop in a daemon thread.
- The gateway uses a paho client thread for MQTT callbacks and a separate flush
  thread. A `threading.Lock` serialises block sealing, so MQTT ingest and HTTP
  ingest can race safely.
- The API runs on uvicorn; blocking work (audit, tamper, reset, snapshot) is
  dispatched with `run_in_threadpool`.
- Node publishers share one paho client; a node thread builds envelopes and
  publishes at its own cadence.
- SQLite writes are serialised; reads use WAL snapshots.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Broker down | gateway reconnects; nodes retry next cycle; dashboard shows MQTT offline |
| Sensor failure | firmware refuses to publish rather than send a fabricated value |
| Clock unsynchronised | firmware refuses to publish |
| Partial batch | sealed at most `block_interval_s` after the oldest pending reading |
| Gateway crash mid-seal | readings stay `pending`; audit flags them after `pending_timeout_s`; block insert is atomic |
| DB tampering | audit reports digest/field/Merkle/link/PoW/quorum failures |
| Replay | duplicate digest rejected; sequence replay rejected |
| Forged signature | rejected and stored for audit |

## Latency budget

`received_at → anchored_at` includes:

1. batching wait (≤ `block_interval_s` when the batch is not full),
2. Merkle root computation (microseconds for 8 leaves),
3. proof-of-work at difficulty 4 (expected ~65k SHA-256 attempts; measured
   ~90 ms average in CPython on this host),
4. three HMAC signatures and SQLite writes.

With fast publishing and full batches, p95 is tens of milliseconds. With the
demo's 2 s node cadence and a 1 s maximum batching wait, p95 is ~1.1–1.2 s. Both
are below the 1.8 s requirement. The benchmark script records the distribution.

## Deployment topologies

**Demo (this repository):** one process, embedded broker, SQLite, simulated
nodes, dashboard on port 12000.

**Pilot:** managed MQTT with TLS and per-device credentials; gateway on a
redundant host; Postgres or SQLite with streaming backups; two independent audit
workers; dashboard behind SSO.

**Production:** devices with secure elements and Ed25519 keys; MQTT over TLS with
certificate pinning; multiple gateway replicas; a permissioned EVM network
running `VaccineLedger.sol`; periodic Merkle-root publication to an external
timestamping service; immutable object storage for raw payloads; 24/7 audit
service with alerting to a SIEM.

## Extending the system

Adding a telemetry field requires coordinated changes:

1. `PAYLOAD_FIELDS` and validation in `vchain/models.py`.
2. `ReadingPayload` and `canonicalPayload` in `firmware/vaccine_node/canonical.h`.
3. The host parity test fixture and `tests/test_canonical_parity.py`.
4. The SQLite column, row builder in `gateway.py`, and API mapping.
5. The Solidity struct/event if the field is committed on-chain.

Adding a policy rule requires a `PolicyViolation` in `vchain/policy.py`, a test,
and (for production) the mirrored check in the contract or an oracle.
