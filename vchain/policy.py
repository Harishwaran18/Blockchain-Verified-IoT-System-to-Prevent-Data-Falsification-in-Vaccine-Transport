"""Cold-chain policy engine.

This is the off-chain mirror of the Solidity `VaccineLedger` contract rules.
Every verdict is recorded in the block header so the policy version that judged
a batch is itself immutable and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .config import Settings
from .models import TelemetryReading, parse_iso, utcnow


@dataclass(frozen=True)
class PolicyViolation:
    code: str
    severity: str  # critical | warning | info
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "message": self.message}


class ColdChainPolicy:
    def __init__(
        self,
        min_temp_c: float = 2.0,
        max_temp_c: float = 8.0,
        humidity_min_pct: float = 20.0,
        humidity_max_pct: float = 80.0,
        max_gap_s: int = 900,
        max_future_skew_s: int = 300,
        max_past_skew_s: int = 86400,
    ) -> None:
        if min_temp_c >= max_temp_c:
            raise ValueError("min_temp_c must be below max_temp_c")
        self.min_temp_c = min_temp_c
        self.max_temp_c = max_temp_c
        self.humidity_min_pct = humidity_min_pct
        self.humidity_max_pct = humidity_max_pct
        self.max_gap_s = max_gap_s
        self.max_future_skew_s = max_future_skew_s
        self.max_past_skew_s = max_past_skew_s

    @classmethod
    def from_settings(cls, settings: Settings) -> "ColdChainPolicy":
        return cls(
            min_temp_c=settings.min_temp_c,
            max_temp_c=settings.max_temp_c,
            humidity_min_pct=settings.humidity_min_pct,
            humidity_max_pct=settings.humidity_max_pct,
            max_gap_s=settings.max_gap_s,
            max_future_skew_s=settings.max_future_skew_s,
            max_past_skew_s=settings.max_past_skew_s,
        )

    def to_dict(self) -> dict:
        """Integer encoding committed into block headers."""
        return {
            "humidity_max_milli_pct": int(round(self.humidity_max_pct * 1000)),
            "humidity_min_milli_pct": int(round(self.humidity_min_pct * 1000)),
            "max_future_skew_s": self.max_future_skew_s,
            "max_gap_s": self.max_gap_s,
            "max_past_skew_s": self.max_past_skew_s,
            "max_temp_centi_c": int(round(self.max_temp_c * 100)),
            "min_temp_centi_c": int(round(self.min_temp_c * 100)),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ColdChainPolicy":
        return cls(
            min_temp_c=data["min_temp_centi_c"] / 100,
            max_temp_c=data["max_temp_centi_c"] / 100,
            humidity_min_pct=data["humidity_min_milli_pct"] / 1000,
            humidity_max_pct=data["humidity_max_milli_pct"] / 1000,
            max_gap_s=data["max_gap_s"],
            max_future_skew_s=data["max_future_skew_s"],
            max_past_skew_s=data["max_past_skew_s"],
        )

    def is_excursion(self, temperature_centi_c: int) -> bool:
        return not (
            int(round(self.min_temp_c * 100)) <= temperature_centi_c <= int(round(self.max_temp_c * 100))
        )

    def evaluate(
        self,
        reading: TelemetryReading,
        previous_seq: int | None = None,
        now: datetime | None = None,
    ) -> list[PolicyViolation]:
        now = now or utcnow()
        violations: list[PolicyViolation] = []
        temp = reading.temperature_centi_c

        if temp > int(round(self.max_temp_c * 100)):
            violations.append(
                PolicyViolation(
                    "TEMPERATURE_HIGH",
                    "critical",
                    f"{reading.temperature_c:.2f} °C exceeds the {self.max_temp_c:.1f} °C upper limit",
                )
            )
        elif temp < int(round(self.min_temp_c * 100)):
            violations.append(
                PolicyViolation(
                    "TEMPERATURE_LOW",
                    "critical",
                    f"{reading.temperature_c:.2f} °C is below the {self.min_temp_c:.1f} °C lower limit",
                )
            )

        if not int(round(self.humidity_min_pct * 1000)) <= reading.humidity_milli_pct <= int(
            round(self.humidity_max_pct * 1000)
        ):
            violations.append(
                PolicyViolation(
                    "HUMIDITY_OUT_OF_RANGE",
                    "warning",
                    f"{reading.humidity_pct:.1f} %RH outside {self.humidity_min_pct:.0f}-{self.humidity_max_pct:.0f} %RH",
                )
            )

        if previous_seq is not None:
            if reading.seq <= previous_seq:
                violations.append(
                    PolicyViolation(
                        "SEQUENCE_REPLAY",
                        "critical",
                        f"sequence {reading.seq} is not greater than last accepted {previous_seq}",
                    )
                )
            elif reading.seq > previous_seq + 1:
                violations.append(
                    PolicyViolation(
                        "SEQUENCE_GAP",
                        "warning",
                        f"sequence jumped from {previous_seq} to {reading.seq}",
                    )
                )

        measured = parse_iso(reading.measured_at)
        skew_s = (measured - now).total_seconds()
        if skew_s > self.max_future_skew_s:
            violations.append(
                PolicyViolation(
                    "TIMESTAMP_FUTURE",
                    "warning",
                    f"timestamp is {skew_s:.0f}s in the future",
                )
            )
        elif -skew_s > self.max_past_skew_s:
            violations.append(
                PolicyViolation(
                    "TIMESTAMP_STALE",
                    "warning",
                    f"timestamp is {-skew_s:.0f}s old",
                )
            )

        if reading.gps_fix == 0:
            violations.append(PolicyViolation("GPS_NO_FIX", "info", "GPS receiver has no fix"))
        elif reading.lat_e7 == 0 and reading.lon_e7 == 0:
            violations.append(PolicyViolation("GPS_NULL_ISLAND", "warning", "GPS fix reports 0,0"))

        return violations
