"""End-to-end benchmark and claim verification.

Runs the real MQTT ingest path, seals difficulty-4 blocks, measures anchoring
latency, executes every tamper attack and checks the battery model.

    python scripts/benchmark.py --readings 240 --rate 80
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import socket
import statistics
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vchain.config import Settings  # noqa: E402
from vchain.fleet import DEVICES  # noqa: E402
from vchain.metrics import BatteryProfile, latency_stats  # noqa: E402
from vchain.node import VirtualVaccineNode  # noqa: E402
from vchain.runtime import VChainRuntime  # noqa: E402

ATTACK_ORDER = [
    "replay",
    "edit_temperature",
    "resign_edit",
    "forge_reading",
    "delete_reading",
    "rewrite_block",
]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(predicate, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="VChain benchmark")
    parser.add_argument("--readings", type=int, default=240)
    parser.add_argument("--rate", type=float, default=80.0, help="readings per second")
    parser.add_argument("--difficulty", type=int, default=4)
    parser.add_argument("--out-dir", default=str(ROOT / "docs"))
    parser.add_argument("--json", action="store_true", help="print JSON instead of a summary")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    workdir = Path(tempfile.mkdtemp(prefix="vchain-bench-"))
    settings = Settings(
        db_path=workdir / "bench.db",
        mqtt_port=free_port(),
        block_size=8,
        block_interval_s=1.0,
        difficulty=args.difficulty,
        validator_count=3,
        quorum=2,
        seed_demo=False,
        start_nodes=False,
        master_secret="benchmark-master-secret",
    )
    runtime = VChainRuntime(settings)
    runtime.start()
    battery = BatteryProfile(
        capacity_mah=settings.battery_capacity_mah,
        active_current_ma=settings.battery_active_ma,
        sleep_current_ma=settings.battery_sleep_ma,
        active_seconds=settings.battery_active_s,
        interval_seconds=settings.node_field_interval_s,
        derating=settings.battery_derating,
    )

    try:
        nodes = [VirtualVaccineNode(profile, settings) for profile in DEVICES]
        topics = [f"vaccine/{profile.device_id}/telemetry" for profile in DEVICES]

        started = time.perf_counter()
        for index in range(args.readings):
            node_index = index % len(nodes)
            runtime.publisher.publish(topics[node_index], nodes[node_index].envelope())
            target = started + (index + 1) / args.rate
            delay = target - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
        publish_seconds = time.perf_counter() - started

        anchored = wait_until(
            lambda: runtime.store.counts()["readings_anchored"] >= args.readings, timeout=90
        )
        total_seconds = time.perf_counter() - started
        counts = runtime.store.counts()
        latencies = runtime.store.latency_values(limit=args.readings + 100)
        stats = latency_stats(latencies)
        first_block = runtime.store.get_block(1)
        mine_times = [row["mine_ms"] for row in runtime.store.all_blocks()[1:]]
        chain_ok_before_attacks = runtime.snapshot()["stats"]["chain_ok"]

        attack_results = []
        for attack in ATTACK_ORDER:
            result = runtime.tamper.run(attack)
            attack_results.append(
                {
                    "attack": attack,
                    "detected": bool(result["detected"]),
                    "findings": sorted({failure["kind"] for failure in result["failures"]}),
                }
            )
        detected = sum(1 for item in attack_results if item["detected"])
        detection_rate = detected / len(attack_results)

        audit = runtime.audit.run()
        checks = {
            "latency_p95_under_1800_ms": stats["p95_ms"] is not None and stats["p95_ms"] < 1800,
            "tamper_detection_100_percent": detection_rate == 1.0,
            "battery_over_72_hours": battery.runtime_hours > 72,
            "all_readings_anchored": anchored and counts["readings_anchored"] >= args.readings,
            "chain_structurally_valid": chain_ok_before_attacks,
        }

        result = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "processor": platform.processor() or "unknown",
                "difficulty": args.difficulty,
                "block_size": settings.block_size,
                "block_interval_s": settings.block_interval_s,
                "validators": settings.validator_count,
                "quorum": settings.quorum,
            },
            "workload": {
                "readings": args.readings,
                "devices": len(DEVICES),
                "publish_rate_per_s": args.rate,
                "publish_seconds": round(publish_seconds, 3),
                "total_seconds": round(total_seconds, 3),
                "throughput_per_s": round(args.readings / total_seconds, 1),
                "blocks": counts["chain_height"],
                "anchored": counts["readings_anchored"],
                "pending": counts["readings_pending"],
                "rejected": counts["readings_rejected"],
                "avg_mine_ms": round(statistics.mean(mine_times), 1) if mine_times else None,
                "max_mine_ms": round(max(mine_times), 1) if mine_times else None,
                "first_block_hash": first_block["hash"] if first_block else None,
            },
            "latency_ms": stats,
            "tamper": {
                "attacks": attack_results,
                "detected": detected,
                "total": len(attack_results),
                "detection_rate": detection_rate,
            },
            "battery": battery.to_dict(),
            "audit_after_attacks": {
                "ok": audit.ok,
                "checks": audit.checks,
                "failures": len(audit.failures),
                "duration_ms": audit.duration_ms,
            },
            "claims": checks,
            "all_claims_pass": all(checks.values()),
        }

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "benchmark.json").write_text(json.dumps(result, indent=2) + "\n")
        (out_dir / "BENCHMARK.md").write_text(render_markdown(result))

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_summary(result)
        return 0 if result["all_claims_pass"] else 1
    finally:
        runtime.stop(close_store=True)
        for path in workdir.glob("*"):
            path.unlink(missing_ok=True)
        workdir.rmdir()


def print_summary(result: dict) -> None:
    latency = result["latency_ms"]
    print("VChain benchmark")
    print("=" * 68)
    print(f"readings        {result['workload']['anchored']} anchored / {result['workload']['readings']} sent")
    print(f"throughput      {result['workload']['throughput_per_s']} readings/s")
    print(f"blocks          {result['workload']['blocks']} (avg seal {result['workload']['avg_mine_ms']} ms)")
    print(
        f"latency         avg {latency['avg_ms']} ms · p50 {latency['p50_ms']} ms · "
        f"p95 {latency['p95_ms']} ms · max {latency['max_ms']} ms"
    )
    print(f"tamper          {result['tamper']['detected']}/{result['tamper']['total']} detected")
    print(f"battery         {result['battery']['runtime_hours']} h ({result['battery']['runtime_days']} days)")
    print("-" * 68)
    for claim, passed in result["claims"].items():
        print(f"[{'PASS' if passed else 'FAIL'}] {claim}")
    print("=" * 68)
    print(f"wrote {ROOT / 'docs' / 'benchmark.json'} and BENCHMARK.md")


def render_markdown(result: dict) -> str:
    latency = result["latency_ms"]
    workload = result["workload"]
    env = result["environment"]
    rows = "\n".join(
        f"| {item['attack']} | {'yes' if item['detected'] else 'no'} | {', '.join(item['findings']) or '—'} |"
        for item in result["tamper"]["attacks"]
    )
    claims = "\n".join(
        f"| {claim.replace('_', ' ')} | {'PASS' if passed else 'FAIL'} |"
        for claim, passed in result["claims"].items()
    )
    return f"""# Benchmark results

Generated {result['generated_at']} by `scripts/benchmark.py`.

These numbers come from the Python reference gateway and embedded MQTT broker
running in this container. They cover the server-side path from MQTT receipt to
sealed block. The ESP32 wake window, GPS acquisition and radio time are modelled
separately in the battery calculation.

## Environment

| Item | Value |
| --- | --- |
| Python | {env['python']} |
| Platform | {env['platform']} |
| Proof-of-work difficulty | {env['difficulty']} leading hex zeros |
| Block size | {env['block_size']} readings |
| Block interval | {env['block_interval_s']} s |
| Validators / quorum | {env['validators']} / {env['quorum']} |

## Workload

| Metric | Value |
| --- | --- |
| Readings published | {workload['readings']} |
| Devices | {workload['devices']} |
| Publish rate | {workload['publish_rate_per_s']} readings/s |
| Publish duration | {workload['publish_seconds']} s |
| Total duration | {workload['total_seconds']} s |
| Throughput | {workload['throughput_per_s']} readings/s |
| Blocks sealed | {workload['blocks']} |
| Anchored / pending / rejected | {workload['anchored']} / {workload['pending']} / {workload['rejected']} |
| Average seal time | {workload['avg_mine_ms']} ms |
| Slowest seal | {workload['max_mine_ms']} ms |

## Anchoring latency

| Metric | ms |
| --- | --- |
| Samples | {latency['n']} |
| Average | {latency['avg_ms']} |
| p50 | {latency['p50_ms']} |
| p95 | {latency['p95_ms']} |
| Max | {latency['max_ms']} |

## Tamper detection

| Attack | Detected | Findings |
| --- | --- | --- |
{rows}

Detection rate: **{result['tamper']['detected']}/{result['tamper']['total']}** ({result['tamper']['detection_rate'] * 100:.0f} %).

## Battery model

| Metric | Value |
| --- | --- |
| Cell capacity | {result['battery']['capacity_mah']} mAh |
| Active / sleep current | {result['battery']['active_current_ma']} mA / {result['battery']['sleep_current_ma']} mA |
| Wake window | {result['battery']['active_seconds']} s |
| Duty cycle | {result['battery']['interval_seconds']} s |
| Average current | {result['battery']['average_current_ma']} mA |
| Projected runtime | {result['battery']['runtime_hours']} h ({result['battery']['runtime_days']} days) |

## Claim verification

| Claim | Result |
| --- | --- |
{claims}

Overall: **{'PASS' if result['all_claims_pass'] else 'FAIL'}**.
"""


if __name__ == "__main__":
    raise SystemExit(main())
