"""Telemetry, signed-envelope and alert models with strict validation.

Sensor values are fixed-point integers (centi-°C, milli-%RH, 1e-7 degrees) so
that the ESP32 and Python encoders produce byte-identical canonical JSON. No
float formatting differences can ever invalidate a hash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .crypto import canonical_json, reading_digest, sha256_hex, sign_reading

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
FIRMWARE_RE = re.compile(r"^[0-9A-Za-z._-]{1,20}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{8,64}$")

PAYLOAD_FIELDS = (
    "device_id",
    "firmware",
    "gps_fix",
    "humidity_milli_pct",
    "lat_e7",
    "lon_e7",
    "measured_at",
    "nonce",
    "seq",
    "temperature_centi_c",
)

ENVELOPE_FIELDS = ("alg", "digest", "payload", "signature")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(moment: datetime) -> str:
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, ISO_FORMAT).replace(tzinfo=timezone.utc)


def epoch_ms(value: str | datetime) -> int:
    moment = parse_iso(value) if isinstance(value, str) else value
    return int(moment.timestamp() * 1000)


@dataclass(frozen=True)
class TelemetryReading:
    device_id: str
    seq: int
    measured_at: str
    temperature_centi_c: int
    humidity_milli_pct: int
    lat_e7: int
    lon_e7: int
    gps_fix: int
    nonce: str
    firmware: str = "1.0.0"

    @property
    def temperature_c(self) -> float:
        return self.temperature_centi_c / 100.0

    @property
    def humidity_pct(self) -> float:
        return self.humidity_milli_pct / 1000.0

    @property
    def lat(self) -> float:
        return self.lat_e7 / 1e7

    @property
    def lon(self) -> float:
        return self.lon_e7 / 1e7

    def to_payload(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in PAYLOAD_FIELDS}

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TelemetryReading":
        problems = validate_payload(payload)
        if problems:
            raise ValueError("; ".join(problems))
        return cls(**{field: payload[field] for field in PAYLOAD_FIELDS})

    @property
    def digest(self) -> str:
        return reading_digest(self.to_payload())

    def signature(self, device_key: str) -> str:
        return sign_reading(device_key, self.digest)

    def envelope(self, device_key: str) -> dict[str, Any]:
        return {
            "alg": "HMAC-SHA256",
            "digest": self.digest,
            "payload": self.to_payload(),
            "signature": self.signature(device_key),
        }


def validate_payload(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["payload must be a JSON object"]
    problems: list[str] = []
    keys = set(payload)
    expected = set(PAYLOAD_FIELDS)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        if missing:
            problems.append(f"missing fields: {', '.join(missing)}")
        if extra:
            problems.append(f"unexpected fields: {', '.join(extra)}")
        return problems

    if not isinstance(payload["device_id"], str) or not DEVICE_RE.match(payload["device_id"]):
        problems.append("device_id must match [A-Za-z0-9_-]{2,32}")
    if not isinstance(payload["firmware"], str) or not FIRMWARE_RE.match(payload["firmware"]):
        problems.append("firmware must match [0-9A-Za-z._-]{1,20}")
    if not isinstance(payload["nonce"], str) or not NONCE_RE.match(payload["nonce"]):
        problems.append("nonce must be 8-64 lowercase hex characters")
    if not isinstance(payload["measured_at"], str) or not ISO_RE.match(payload["measured_at"]):
        problems.append("measured_at must be UTC ISO-8601 with milliseconds, e.g. 2026-01-01T00:00:00.000Z")
    else:
        try:
            parse_iso(payload["measured_at"])
        except ValueError:
            problems.append("measured_at is not a valid timestamp")

    for field in ("seq", "temperature_centi_c", "humidity_milli_pct", "lat_e7", "lon_e7", "gps_fix"):
        if isinstance(payload[field], bool) or not isinstance(payload[field], int):
            problems.append(f"{field} must be an integer")

    if not problems:
        if payload["seq"] < 0:
            problems.append("seq must be >= 0")
        if not -5000 <= payload["temperature_centi_c"] <= 6000:
            problems.append("temperature_centi_c outside plausible sensor range (-50..60 C)")
        if not 0 <= payload["humidity_milli_pct"] <= 100_000:
            problems.append("humidity_milli_pct outside 0..100 %RH")
        if not -900_000_000 <= payload["lat_e7"] <= 900_000_000:
            problems.append("lat_e7 outside -90..90 degrees")
        if not -1_800_000_000 <= payload["lon_e7"] <= 1_800_000_000:
            problems.append("lon_e7 outside -180..180 degrees")
        if payload["gps_fix"] not in (0, 1):
            problems.append("gps_fix must be 0 or 1")
    return problems


@dataclass(frozen=True)
class SignedEnvelope:
    payload: dict[str, Any]
    digest: str
    signature: str
    alg: str = "HMAC-SHA256"

    @classmethod
    def from_dict(cls, data: Any) -> "SignedEnvelope":
        if not isinstance(data, dict):
            raise ValueError("envelope must be a JSON object")
        if set(data) != set(ENVELOPE_FIELDS):
            raise ValueError("envelope must contain exactly: " + ", ".join(ENVELOPE_FIELDS))
        if data["alg"] != "HMAC-SHA256":
            raise ValueError(f"unsupported signature algorithm: {data['alg']!r}")
        if not isinstance(data["digest"], str) or not HEX64_RE.match(data["digest"]):
            raise ValueError("digest must be 64 lowercase hex characters")
        if not isinstance(data["signature"], str) or not HEX64_RE.match(data["signature"]):
            raise ValueError("signature must be 64 lowercase hex characters")
        problems = validate_payload(data["payload"])
        if problems:
            raise ValueError("; ".join(problems))
        return cls(payload=data["payload"], digest=data["digest"], signature=data["signature"], alg=data["alg"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "alg": self.alg,
            "digest": self.digest,
            "payload": self.payload,
            "signature": self.signature,
        }

    @property
    def reading(self) -> TelemetryReading:
        return TelemetryReading.from_payload(self.payload)

    def check_digest(self) -> bool:
        return reading_digest(self.payload) == self.digest

    def check_signature(self, device_key: str) -> bool:
        return sign_reading(device_key, self.digest) == self.signature


@dataclass(frozen=True)
class Alert:
    kind: str
    severity: str
    device_id: str
    reading_digest: str
    message: str
    created_at: str

    def core(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "device_id": self.device_id,
            "kind": self.kind,
            "message": self.message,
            "reading_digest": self.reading_digest,
            "severity": self.severity,
        }

    @property
    def alert_digest(self) -> str:
        return sha256_hex(canonical_json(self.core()))

    def to_dict(self) -> dict[str, Any]:
        return {**self.core(), "alert_digest": self.alert_digest}


def recent_cutoff(seconds: int, now: datetime | None = None) -> datetime:
    return (now or utcnow()) - timedelta(seconds=seconds)
