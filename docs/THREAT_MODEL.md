# Threat model

VChain is designed for the specific threat that matters in pharmaceutical
logistics: **an insider or operator changing the record after the fact to hide a
temperature excursion**. It is not a substitute for sensor security, device
attestation or organisational controls.

## Assets

| Asset | Why it matters |
| --- | --- |
| Temperature/humidity history | determines whether a vaccine batch is usable |
| Excursion and alert evidence | supports regulatory and contractual decisions |
| Device authenticity | prevents an unauthorised node from injecting readings |
| Chain history and ordering | proves what was known, and when |
| Device and validator keys | authorise readings and block finalisation |
| Audit availability | detection is worthless if evidence cannot be checked |

## Trust boundaries

```text
 physical world        MCU firmware          network              server
┌──────────────┐   ┌────────────────┐   ┌──────────────┐   ┌──────────────────┐
│ DHT22 / GPS  │──▶│ canonicalise   │──▶│ MQTT broker  │──▶│ gateway → ledger │
│ (untrusted)  │   │ hash + sign    │   │ (TLS)        │   │ (trusted compute)│
└──────────────┘   └────────────────┘   └──────────────┘   └────────┬─────────┘
                                                                     │
                                                          ┌──────────▼─────────┐
                                                          │ independent audit  │
                                                          │ (trusts only keys) │
                                                          └────────────────────┘
```

The audit engine trusts only: the master secret (to derive device keys), the
validator public keys/keys, and the bytes it reads. It does not trust the
gateway, the database schema, or any cached verdict.

## Adversaries and detection

| # | Adversary | Capability | Detection | Residual risk |
| --- | --- | --- | --- | --- |
| A1 | Insider DBA | read/write SQLite, edit or delete rows | reading digest mismatch, field mismatch, Merkle/block mismatch, missing anchored row, alert digest mismatch | can delete the entire database; needs an external replica/anchor to prove what was lost |
| A2 | Network attacker | inject, modify, replay MQTT packets | schema rejection, digest mismatch, HMAC failure, duplicate digest, sequence replay | can drop packets (availability), which shows as a sequence gap or missing expected cadence |
| A3 | Thief with a device key | sign arbitrary readings as that device | cannot be detected by the gateway — the signature is valid | requires secure element, key rotation, anomaly detection, physical tamper evidence |
| A4 | Malicious gateway operator | suppress a reading before anchoring, reorder batches | sequence gaps, missing expected readings, audit of alerts vs policy, independent gateways | can withhold data; cannot forge a past reading or alter an anchored one without breaking the chain |
| A5 | Colluding validators | ≥ quorum sign a false block | nothing in a single-node demo | use independent operators, geographically distributed validators, external transparency log |
| A6 | Firmware attacker | flash altered firmware, reuse keys | measured boot / secure boot, signed firmware, remote attestation | out of scope for the Python demo |
| A7 | Ransomware / deletion | drop tables or delete the DB file | audit cannot run; external Merkle-root anchor or replicated ledger proves the tip | requires off-host replication and backups |
| A8 | Time-source attacker | spoof NTP to backdate readings | gateway checks future/past skew; GPS UTC cross-check | needs authenticated time (GNSS + RTC + NTS) |
| A9 | Replay of a valid packet | double-count a compliant reading | digest is a primary key; `DUPLICATE_REPLAY`; sequence must increase | none at the ledger layer |

## Cryptographic properties relied upon

| Property | Mechanism |
| --- | --- |
| Collision resistance | SHA-256 for payload digests, Merkle nodes, block hashes |
| Authenticity | HMAC-SHA256 with per-device derived keys |
| Domain separation | distinct prefixes for reading signatures, block signatures and Merkle leaves/nodes |
| Binding | Merkle root commits to the exact ordered set of reading digests |
| Immutability | hash chain + proof-of-work + validator quorum + committed policy |
| Replay resistance | digest primary key and monotonic per-device sequence |
| Non-repudiation of alerts | alert digest committed in the block header |

HMAC is symmetric: a gateway that holds the master secret can also forge device
signatures. Production deployments should use per-device asymmetric keys
(Ed25519/ECDSA) so the verifier never holds signing capability.

## What the tamper lab demonstrates

| Attack | Layer | What the attacker gains if undetected | What actually happens |
| --- | --- | --- | --- |
| `edit_temperature` | SQLite | hides an excursion | payload no longer hashes to the stored digest |
| `resign_edit` | SQLite + stolen key | plausible signature on a false reading | new digest is absent from the block's Merkle root |
| `forge_reading` | SQLite | inserts a compliant reading | signature fails and digest is not committed |
| `delete_reading` | SQLite | removes inconvenient evidence | block commits a digest whose row is gone |
| `rewrite_block` | block table | erases a reading from a block | PoW target fails, downstream link breaks, quorum is lost |
| `replay` | MQTT | double-counts a compliant reading | duplicate digest rejected before anchoring |

Every attack is recorded in `tamper_events` with the exact audit findings, so the
failed falsification attempt itself becomes evidence.

## Out of scope

- **Sensor spoofing before signing.** A heater or a fake DHT22 can produce a
  genuine-looking 5 °C reading. Mitigations: sensor plausibility models, dual
  sensors, enclosure tamper switches.
- **Compromised device keys.** Detectable only with hardware-backed keys,
  attestation and anomaly detection.
- **Majority validator collusion.** Requires independent governance and an
  external transparency log.
- **Denial of service and traffic analysis.** MQTT broker hardening, rate limits
  and network segmentation are deployment concerns.
- **Privacy of location data.** GPS traces are personal data in many
  jurisdictions; production needs access control and retention policy.
- **Regulatory qualification.** This is a research reference, not a validated
  GxP system.

## Audit procedure for a regulator or counterparty

1. Download `/api/export` from the operator and, independently, obtain the
   expected genesis hash and latest block hash from a second party.
2. For each reading, recompute
   `SHA-256("VCHAIN/reading/v1:" ‖ canonical_payload)` and compare it with the
   digest.
3. Verify the HMAC signature with the device key (or public key in production).
4. Rebuild each block's Merkle root from its committed digest list.
5. Recompute each block hash, check the leading-zero target, the `prev_hash`
   link and the validator signatures/quorum.
6. Recompute each alert digest and confirm it is committed in the claimed block.
7. Confirm every committed digest has a reading row, and every anchored row has
   a valid inclusion proof.
8. Compare the exported tip with the external anchor or a replica.

The same checks are implemented in `vchain/audit.py` and can be run with one
button or `POST /api/audit`.

## Hardening roadmap

| Priority | Change |
| --- | --- |
| P0 | Replace HMAC device keys with Ed25519; store private keys in ATECC608A |
| P0 | MQTT over TLS with mutual authentication and certificate pinning |
| P0 | Replicate the ledger and publish Merkle roots to an external timestamp anchor |
| P1 | Secure boot, signed firmware and remote attestation |
| P1 | Separate validator operators and an on-chain quorum (see the Solidity contract) |
| P1 | Authenticated time (GNSS + NTS) and clock-drift monitoring |
| P2 | Dual-sensor plausibility checks and enclosure tamper detection |
| P2 | SIEM integration, anomaly detection on sequence cadence and temperature profiles |
| P2 | Role-based access control, SSO and audit-log export for the dashboard |
