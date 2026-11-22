from __future__ import annotations

import pytest

from vchain.crypto import reading_digest
from vchain.models import (
    Alert,
    SignedEnvelope,
    TelemetryReading,
    epoch_ms,
    iso_z,
    parse_iso,
    utcnow,
    validate_payload,
)


def payload(**overrides):
    base = {
        "device_id": "VX-001",
        "firmware": "1.0.0",
        "gps_fix": 1,
        "humidity_milli_pct": 45250,
        "lat_e7": 407128000,
        "lon_e7": -740059000,
        "measured_at": "2026-11-22T09:10:00.123Z",
        "nonce": "a1b2c3d4e5f60718",
        "seq": 42,
        "temperature_centi_c": 512,
    }
    base.update(overrides)
    return base


def test_reading_properties_and_roundtrip():
    reading = TelemetryReading.from_payload(payload())
    assert reading.temperature_c == 5.12
    assert reading.humidity_pct == 45.25
    assert reading.lat == 40.7128
    assert reading.lon == -74.0059
    assert reading.to_payload() == payload()
    assert reading.digest == reading_digest(payload())


def test_timestamp_helpers():
    moment = utcnow()
    text = iso_z(moment)
    assert len(text) == 24 and text.endswith("Z")
    assert parse_iso(text).timestamp() == pytest.approx(moment.timestamp(), abs=0.001)
    assert epoch_ms(text) > 0


def test_envelope_roundtrip_and_checks():
    reading = TelemetryReading.from_payload(payload())
    envelope = SignedEnvelope.from_dict(reading.envelope("secret-key"))
    assert envelope.payload == payload()
    assert envelope.check_digest()
    assert envelope.check_signature("secret-key")
    assert not envelope.check_signature("other-key")
    assert envelope.reading == reading
    assert envelope.to_dict()["alg"] == "HMAC-SHA256"


@pytest.mark.parametrize(
    "overrides",
    [
        {"device_id": "bad id!"},
        {"firmware": ""},
        {"gps_fix": 2},
        {"humidity_milli_pct": 100_001},
        {"humidity_milli_pct": -1},
        {"lat_e7": 900_000_001},
        {"lon_e7": -1_800_000_001},
        {"measured_at": "2026-11-22 09:10:00"},
        {"measured_at": "2026-13-22T09:10:00.123Z"},
        {"nonce": "XYZ"},
        {"seq": -1},
        {"temperature_centi_c": 6001},
        {"temperature_centi_c": -5001},
    ],
)
def test_payload_validation_rejects_bad_values(overrides):
    problems = validate_payload(payload(**overrides))
    assert problems


def test_payload_validation_rejects_missing_and_extra_fields():
    missing = payload()
    missing.pop("nonce")
    assert validate_payload(missing)
    extra = payload()
    extra["injected"] = 1
    assert validate_payload(extra)


def test_payload_validation_rejects_non_integers():
    assert validate_payload(payload(temperature_centi_c=5.12))
    assert validate_payload(payload(seq=True))


def test_payload_validation_rejects_non_object():
    assert validate_payload([])
    assert validate_payload("nope")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: {**e, "alg": "SHA1"},
        lambda e: {**e, "digest": "xyz"},
        lambda e: {**e, "signature": "abc"},
        lambda e: {k: v for k, v in e.items() if k != "payload"},
        lambda e: {**e, "extra": 1},
    ],
)
def test_envelope_schema_rejects_bad_shapes(mutate):
    reading = TelemetryReading.from_payload(payload())
    envelope = reading.envelope("key")
    with pytest.raises(ValueError):
        SignedEnvelope.from_dict(mutate(envelope))


def test_alert_digest_is_deterministic_and_sensitive():
    alert = Alert(
        kind="TEMPERATURE_HIGH",
        severity="critical",
        device_id="VX-001",
        reading_digest="a" * 64,
        message="too hot",
        created_at="2026-01-01T00:00:00.000Z",
    )
    assert alert.alert_digest == alert.alert_digest
    changed = Alert(**{**alert.__dict__, "message": "too cold"})
    assert changed.alert_digest != alert.alert_digest
    assert alert.to_dict()["alert_digest"] == alert.alert_digest
