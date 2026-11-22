"""Pharmaceutical metrics and the ESP32 power model."""

from __future__ import annotations

import math
from dataclasses import dataclass

# Mean kinetic temperature constants (ICH Q1A / USP <1150>).
DELTA_H_J_MOL = 83_144.0
GAS_CONSTANT = 8.314472
KELVIN_OFFSET = 273.15


def mean_kinetic_temperature(temperatures_c: list[float]) -> float | None:
    """Arrhenius-weighted mean temperature in °C, the metric regulators use."""
    if not temperatures_c:
        return None
    kelvins = [t + KELVIN_OFFSET for t in temperatures_c]
    if any(k <= 0 for k in kelvins):
        return None
    mean_exp = sum(math.exp(-DELTA_H_J_MOL / (GAS_CONSTANT * k)) for k in kelvins) / len(kelvins)
    if mean_exp <= 0:
        return None
    return DELTA_H_J_MOL / (GAS_CONSTANT * -math.log(mean_exp)) - KELVIN_OFFSET


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency_stats(values: list[float]) -> dict:
    if not values:
        return {"avg_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None, "n": 0}
    return {
        "avg_ms": round(sum(values) / len(values), 2),
        "p50_ms": round(percentile(values, 0.50), 2),
        "p95_ms": round(percentile(values, 0.95), 2),
        "max_ms": round(max(values), 2),
        "n": len(values),
    }


@dataclass(frozen=True)
class BatteryProfile:
    """Duty-cycled ESP32 node: wake, sample, hash, transmit, deep sleep."""

    capacity_mah: float = 2500.0
    active_current_ma: float = 120.0
    sleep_current_ma: float = 0.05
    active_seconds: float = 1.5
    interval_seconds: float = 30.0
    derating: float = 0.85

    def __post_init__(self) -> None:
        if self.interval_seconds <= self.active_seconds:
            raise ValueError("interval must exceed the active window")
        if not 0 < self.derating <= 1:
            raise ValueError("derating must be in (0, 1]")

    @property
    def sleep_seconds(self) -> float:
        return self.interval_seconds - self.active_seconds

    @property
    def average_current_ma(self) -> float:
        charge = self.active_current_ma * self.active_seconds + self.sleep_current_ma * self.sleep_seconds
        return charge / self.interval_seconds

    @property
    def runtime_hours(self) -> float:
        usable = self.capacity_mah * self.derating
        return usable / self.average_current_ma

    @property
    def runtime_days(self) -> float:
        return self.runtime_hours / 24

    @property
    def energy_per_reading_j(self) -> float:
        # Assume a 3.7 V Li-ion cell; 1 mAh at 3.7 V = 13.32 J.
        charge_mah = self.average_current_ma * self.interval_seconds / 3600
        return charge_mah * 3.7 * 3.6

    def to_dict(self) -> dict:
        return {
            "capacity_mah": self.capacity_mah,
            "active_current_ma": self.active_current_ma,
            "sleep_current_ma": self.sleep_current_ma,
            "active_seconds": self.active_seconds,
            "interval_seconds": self.interval_seconds,
            "average_current_ma": round(self.average_current_ma, 3),
            "runtime_hours": round(self.runtime_hours, 1),
            "runtime_days": round(self.runtime_days, 1),
            "energy_per_reading_j": round(self.energy_per_reading_j, 3),
        }
