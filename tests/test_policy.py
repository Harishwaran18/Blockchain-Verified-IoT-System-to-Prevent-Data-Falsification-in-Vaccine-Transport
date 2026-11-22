from __future__ import annotations

from datetime import timedelta

from vchain.config import Settings
from vchain.models import TelemetryReading, iso_z, utcnow
from vchain.policy import ColdChainPolicy


def reading(**overrides):
    now = overrides.pop("now", utcnow())
    base = {
        "device_id": "VX-001",
        "firmware": "1.0.0",
        "gps_fix": 1,
        "humidity_milli_pct": 45000,
        "lat_e7": -12921000,
        "lon_e7": 368219000,
        "measured_at": iso_z(now),
        "nonce": "0011223344556677",
        "seq": 10,
        "temperature_centi_c": 500,
    }
    base.update(overrides)
    return TelemetryReading.from_payload(base), now


def codes(violations):
    return {violation.code for violation in violations}


def test_policy_accepts_normal_reading():
    item, now = reading()
    assert ColdChainPolicy().evaluate(item, previous_seq=9, now=now) == []


def test_high_and_low_temperature_are_critical():
    policy = ColdChainPolicy()
    hot, now = reading(temperature_centi_c=850)
    cold, _ = reading(temperature_centi_c=150)
    assert "TEMPERATURE_HIGH" in codes(policy.evaluate(hot, now=now))
    assert "TEMPERATURE_LOW" in codes(policy.evaluate(cold, now=now))
    assert policy.evaluate(hot, now=now)[0].severity == "critical"
    assert policy.is_excursion(850)
    assert policy.is_excursion(150)
    assert not policy.is_excursion(800)


def test_humidity_range():
    policy = ColdChainPolicy()
    dry, now = reading(humidity_milli_pct=10000)
    wet, _ = reading(humidity_milli_pct=90000)
    assert "HUMIDITY_OUT_OF_RANGE" in codes(policy.evaluate(dry, now=now))
    assert "HUMIDITY_OUT_OF_RANGE" in codes(policy.evaluate(wet, now=now))


def test_sequence_replay_and_gap():
    policy = ColdChainPolicy()
    item, now = reading(seq=5)
    assert "SEQUENCE_REPLAY" in codes(policy.evaluate(item, previous_seq=5, now=now))
    assert "SEQUENCE_REPLAY" in codes(policy.evaluate(item, previous_seq=9, now=now))
    gap, _ = reading(seq=50)
    assert "SEQUENCE_GAP" in codes(policy.evaluate(gap, previous_seq=10, now=now))


def test_timestamp_skew():
    policy = ColdChainPolicy()
    future, now = reading(measured_at=iso_z(utcnow() + timedelta(hours=1)))
    assert "TIMESTAMP_FUTURE" in codes(policy.evaluate(future, now=now))
    stale, _ = reading(measured_at=iso_z(utcnow() - timedelta(days=3)))
    assert "TIMESTAMP_STALE" in codes(policy.evaluate(stale, now=now))


def test_gps_checks():
    policy = ColdChainPolicy()
    no_fix, now = reading(gps_fix=0, lat_e7=0, lon_e7=0)
    assert "GPS_NO_FIX" in codes(policy.evaluate(no_fix, now=now))
    null_island, _ = reading(gps_fix=1, lat_e7=0, lon_e7=0)
    assert "GPS_NULL_ISLAND" in codes(policy.evaluate(null_island, now=now))


def test_policy_dict_roundtrip():
    policy = ColdChainPolicy(min_temp_c=3.0, max_temp_c=7.0)
    restored = ColdChainPolicy.from_dict(policy.to_dict())
    assert restored.min_temp_c == 3.0
    assert restored.max_temp_c == 7.0
    assert restored.to_dict() == policy.to_dict()


def test_policy_from_settings():
    settings = Settings(min_temp_c=2.5, max_temp_c=7.5)
    policy = ColdChainPolicy.from_settings(settings)
    assert policy.min_temp_c == 2.5
    assert policy.max_temp_c == 7.5


def test_policy_rejects_inverted_range():
    import pytest

    with pytest.raises(ValueError):
        ColdChainPolicy(min_temp_c=8.0, max_temp_c=2.0)
