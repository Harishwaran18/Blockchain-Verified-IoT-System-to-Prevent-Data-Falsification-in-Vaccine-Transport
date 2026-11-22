# HTTP API

Base URL: `http://localhost:12000`. All responses are JSON unless noted.
The demo has no authentication; put it behind SSO and TLS before exposing it.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | dashboard |
| GET | `/api/health` | liveness, MQTT state, chain height |
| GET | `/api/snapshot` | everything the dashboard needs |
| GET | `/api/readings?limit=&device_id=&status=` | recent readings |
| GET | `/api/readings/{digest}` | payload, signature, proof and verification checks |
| GET | `/api/blocks?limit=` | recent block headers |
| GET | `/api/blocks/{index}` | block, committed readings, alerts and checks |
| GET | `/api/alerts?limit=` | alert feed |
| POST | `/api/audit` | run the full audit |
| GET | `/api/audit/latest` | most recent audit |
| GET | `/api/tamper` | attack catalogue and history |
| POST | `/api/tamper/{attack}` | run one attack, then audit |
| POST | `/api/reset` | rebuild the ledger from genesis and re-seed |
| POST | `/api/excursion` | toggle a simulated node excursion |
| POST | `/api/ingest` | submit a signed envelope (HTTP fallback for devices) |
| GET | `/api/chain/verify` | structural chain validation only |
| GET | `/api/export` | downloadable audit bundle |
| GET | `/api/policy` | policy and commitment parameters |

## Health

```bash
curl -s localhost:12000/api/health
```

```json
{"ok": true, "mqtt_connected": true, "chain_height": 27, "uptime_s": 42}
```

## Snapshot

```bash
curl -s localhost:12000/api/snapshot
```

Top-level keys: `now`, `network`, `stats`, `policy`, `battery`, `devices`,
`readings`, `blocks`, `alerts`, `series`, `audit`, `tamper_events`, `attacks`,
`chain_issues`.

`stats.latency` contains `avg_ms`, `p50_ms`, `p95_ms`, `max_ms` and `n` over
live MQTT readings. `stats.detection_rate` is `null` until an attack is run.

## Reading detail

```bash
curl -s localhost:12000/api/readings/<digest>
```

```json
{
  "reading": {
    "digest": "…",
    "device_id": "VX-001",
    "seq": 31,
    "measured_at": "2026-11-22T09:27:45.000Z",
    "temperature_c": 5.26,
    "humidity_pct": 47.0,
    "lat": -1.3,
    "lon": 36.8,
    "block_index": 24,
    "status": "anchored",
    "latency_ms": 1124.0
  },
  "payload": {"…": "the exact signed fixed-point payload"},
  "signature": "…",
  "block": {"index": 24, "hash": "…", "merkle_root": "…", "…": "…"},
  "proof": {
    "digest": "…",
    "block_index": 24,
    "merkle_root": "…",
    "leaf_index": 2,
    "proof": [{"position": "left", "hash": "…"}],
    "verified": true
  },
  "checks": {
    "payload_digest_ok": true,
    "signature_ok": true,
    "merkle_ok": true,
    "block_hash_ok": true,
    "proof_of_work_ok": true,
    "validator_quorum_ok": true,
    "anchored": true,
    "verified": true
  }
}
```

Pending readings return `verified: false` with `anchored: false`; that is not an
integrity failure, just an unsealed reading.

## Blocks

```bash
curl -s localhost:12000/api/blocks/24
```

Returns `block`, `readings`, `alerts`, `checks` (`block_hash_ok`, `merkle_ok`,
`proof_of_work_ok`, `validator_signatures_valid`, `validator_quorum_ok`,
`prev_link_ok`, `readings_present`) and `invalid_validators`.

## Audit

```bash
curl -s -X POST localhost:12000/api/audit
```

```json
{
  "id": 12,
  "ok": true,
  "checks": 892,
  "readings_checked": 136,
  "blocks_checked": 27,
  "alerts_checked": 3,
  "duration_ms": 6.1,
  "failure_count": 0,
  "failures": []
}
```

Each failure has `kind`, `severity`, `block_index`, `detail`, `expected`,
`actual`.

## Tamper lab

```bash
curl -s localhost:12000/api/tamper
curl -s -X POST localhost:12000/api/tamper/edit_temperature
```

Attacks: `edit_temperature`, `resign_edit`, `forge_reading`, `delete_reading`,
`rewrite_block`, `replay`.

```json
{
  "attack": "edit_temperature",
  "name": "Naive temperature edit",
  "layer": "off-chain database",
  "description": "Changed reading … from 9.37 °C to 3.50 °C …",
  "detected": true,
  "duration_ms": 18.0,
  "failures": [{"kind": "READING_DIGEST_MISMATCH", "…": "…"}],
  "report": {"ok": false, "checks": 992, "failure_count": 1}
}
```

Attacks are destructive and stay in the ledger as evidence. `POST /api/reset`
restores a clean demo.

## Reset

```bash
curl -s -X POST localhost:12000/api/reset
```

```json
{"ok": true, "genesis_hash": "0000…"}
```

Rebuilds the schema, creates a new genesis block and re-seeds demo readings when
`VCHAIN_SEED_DEMO=1`. Tamper events and audit history are cleared.

## Excursion

```bash
curl -s -X POST localhost:12000/api/excursion \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"VX-002","active":true}'
```

The simulated node reports ~9.4 °C until `active` is set to `false`.

## Ingest

Useful for an ESP32 that publishes over HTTPS instead of MQTT.

```bash
curl -s -X POST localhost:12000/api/ingest \
  -H 'Content-Type: application/json' \
  -d @envelope.json
```

The body is the exact envelope published to MQTT:

```json
{
  "alg": "HMAC-SHA256",
  "digest": "<64 hex>",
  "payload": {"device_id": "VX-001", "…": "…"},
  "signature": "<64 hex>"
}
```

- `200` with `{"accepted": true, "digest": "…", "violations": []}`
- `422` with `{"detail": {"reason": "SIGNATURE_INVALID", "digest": "…"}}` for a
  rejected packet
- `422` with a schema message for malformed JSON

## Export

```bash
curl -s -OJ localhost:12000/api/export
```

Downloads `vchain-audit-bundle.json` with the genesis hash, policy, chain
issues, block headers, reading metadata, alerts, tamper events and the latest
audit. Raw payloads and signatures are included so an independent auditor can
recompute everything.

## Errors

| Status | Meaning |
| --- | --- |
| `404` | unknown block, reading, attack or device |
| `409` | attack cannot run yet (for example, no sealed block to rewrite) |
| `422` | envelope rejected or schema invalid |
| `500` | unexpected server error |
