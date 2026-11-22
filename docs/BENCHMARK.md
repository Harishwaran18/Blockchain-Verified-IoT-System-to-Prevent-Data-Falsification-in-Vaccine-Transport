# Benchmark results

Generated 2026-11-22T09:35:38+00:00 by `scripts/benchmark.py`.

These numbers come from the Python reference gateway and embedded MQTT broker
running in this container. They cover the server-side path from MQTT receipt to
sealed block. The ESP32 wake window, GPS acquisition and radio time are modelled
separately in the battery calculation.

## Environment

| Item | Value |
| --- | --- |
| Python | 3.13.15 |
| Platform | Linux-6.8.0-1055-gke-x86_64-with-glibc2.41 |
| Proof-of-work difficulty | 4 leading hex zeros |
| Block size | 8 readings |
| Block interval | 1.0 s |
| Validators / quorum | 3 / 2 |

## Workload

| Metric | Value |
| --- | --- |
| Readings published | 240 |
| Devices | 4 |
| Publish rate | 80.0 readings/s |
| Publish duration | 3.005 s |
| Total duration | 3.193 s |
| Throughput | 75.2 readings/s |
| Blocks sealed | 30 |
| Anchored / pending / rejected | 240 / 0 / 0 |
| Average seal time | 90.9 ms |
| Slowest seal | 428.8 ms |

## Anchoring latency

| Metric | ms |
| --- | --- |
| Samples | 240 |
| Average | 7.53 |
| p50 | 2.0 |
| p95 | 38.4 |
| Max | 88.0 |

## Tamper detection

| Attack | Detected | Findings |
| --- | --- | --- |
| replay | yes | REPLAY_REJECTED |
| edit_temperature | yes | READING_DIGEST_MISMATCH |
| resign_edit | yes | ANCHORED_READING_MISSING, READING_NOT_IN_BLOCK |
| forge_reading | yes | READING_NOT_IN_BLOCK, READING_SIGNATURE_INVALID |
| delete_reading | yes | ANCHORED_READING_MISSING |
| rewrite_block | yes | BLOCK_LINK_BROKEN, BLOCK_POW_INVALID, BLOCK_QUORUM_FAILURE, READING_NOT_IN_BLOCK |

Detection rate: **6/6** (100 %).

## Battery model

| Metric | Value |
| --- | --- |
| Cell capacity | 2500.0 mAh |
| Active / sleep current | 120.0 mA / 0.05 mA |
| Wake window | 4.0 s |
| Duty cycle | 30.0 s |
| Average current | 16.043 mA |
| Projected runtime | 132.5 h (5.5 days) |

## Claim verification

| Claim | Result |
| --- | --- |
| latency p95 under 1800 ms | PASS |
| tamper detection 100 percent | PASS |
| battery over 72 hours | PASS |
| all readings anchored | PASS |
| chain structurally valid | PASS |

Overall: **PASS**.
