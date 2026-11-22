from __future__ import annotations

import pytest

from vchain.metrics import (
    BatteryProfile,
    latency_stats,
    mean_kinetic_temperature,
    percentile,
)


def test_battery_profile_exceeds_72_hours():
    battery = BatteryProfile()
    assert battery.runtime_hours > 72
    assert battery.runtime_days > 3
    assert 0 < battery.average_current_ma < 20
    assert battery.energy_per_reading_j > 0
    payload = battery.to_dict()
    assert payload["runtime_hours"] > 72
    assert payload["interval_seconds"] == 30


def test_battery_profile_rejects_invalid_windows():
    import pytest

    with pytest.raises(ValueError):
        BatteryProfile(interval_seconds=1, active_seconds=2)
    with pytest.raises(ValueError):
        BatteryProfile(derating=0)


def test_battery_life_scales_with_interval():
    slow = BatteryProfile(interval_seconds=60)
    fast = BatteryProfile(interval_seconds=15)
    assert slow.runtime_hours > fast.runtime_hours


def test_mean_kinetic_temperature_constant_is_exact():
    assert mean_kinetic_temperature([5.0] * 20) == pytest.approx(5.0)
    assert mean_kinetic_temperature([]) is None


def test_mean_kinetic_temperature_penalises_excursions():
    compliant = mean_kinetic_temperature([5.0] * 20)
    excursion = mean_kinetic_temperature([5.0] * 18 + [9.5, 9.5])
    assert excursion > compliant


def test_percentiles_and_latency_stats():
    values = [float(i) for i in range(1, 101)]
    assert percentile(values, 0.5) == 50.5
    assert percentile(values, 0.95) == 95.05
    assert percentile([], 0.5) is None
    stats = latency_stats(values)
    assert stats["n"] == 100
    assert stats["p95_ms"] == 95.05
    assert stats["max_ms"] == 100.0
    empty = latency_stats([])
    assert empty["n"] == 0 and empty["avg_ms"] is None
