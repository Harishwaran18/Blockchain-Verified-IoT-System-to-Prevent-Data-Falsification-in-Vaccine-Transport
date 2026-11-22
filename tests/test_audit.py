from __future__ import annotations

import pytest

from vchain.tamper import ATTACKS

ATTACK_KEYS = [attack.key for attack in ATTACKS]


def seeded(runtime, readings: int = 4):
    runtime.seed_demo(readings_per_device=readings)
    report = runtime.audit.run()
    assert report.ok, report.failures
    return report


def test_clean_audit_covers_readings_blocks_and_alerts(runtime):
    report = seeded(runtime, readings=6)
    assert report.blocks_checked >= 6
    assert report.readings_checked == 24
    assert report.alerts_checked >= 0
    assert report.checks > report.readings_checked
    latest = runtime.audit.latest()
    assert latest["ok"] is True
    assert latest["failure_count"] == 0


@pytest.mark.parametrize("attack", ATTACK_KEYS)
def test_every_attack_is_detected(runtime, attack):
    seeded(runtime)
    result = runtime.tamper.run(attack)
    assert result["detected"], result
    assert result["failures"], result
    stats = runtime.store.tamper_stats()
    assert stats == {"total": 1, "detected": 1}
    assert result["report"]["ok"] is (attack == "replay")


@pytest.mark.parametrize(
    "attack,expected",
    [
        ("edit_temperature", "READING_DIGEST_MISMATCH"),
        ("resign_edit", "ANCHORED_READING_MISSING"),
        ("forge_reading", "READING_SIGNATURE_INVALID"),
        ("delete_reading", "ANCHORED_READING_MISSING"),
        ("rewrite_block", "BLOCK_POW_INVALID"),
        ("replay", "REPLAY_REJECTED"),
    ],
)
def test_attack_specific_findings(runtime, attack, expected):
    seeded(runtime)
    result = runtime.tamper.run(attack)
    kinds = {failure["kind"] for failure in result["failures"]}
    assert expected in kinds, kinds


def test_reset_restores_a_clean_ledger(runtime):
    from dataclasses import replace

    seeded(runtime)
    runtime.tamper.run("delete_reading")
    assert runtime.store.tamper_stats()["total"] == 1

    runtime.settings = replace(runtime.settings, seed_demo=True)
    runtime.reset()

    snapshot = runtime.snapshot()
    assert snapshot["stats"]["readings_total"] > 0
    assert snapshot["stats"]["chain_height"] >= 1
    assert snapshot["stats"]["tamper_attempts"] == 0
    assert snapshot["stats"]["chain_ok"] is True
    assert snapshot["audit"] is None
    report = runtime.audit.run()
    assert report.ok, report.failures
    assert runtime.store.tamper_stats() == {"total": 0, "detected": 0}


def test_unknown_attack_raises(runtime):
    with pytest.raises(KeyError):
        runtime.tamper.run("rm -rf")
