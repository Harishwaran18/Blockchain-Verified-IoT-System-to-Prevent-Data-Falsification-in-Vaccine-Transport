"""Virtual ESP32 vaccine-transport nodes.

The simulator reproduces the firmware's payload construction exactly: fixed-point
sensor values, millisecond UTC timestamps, a random nonce and HMAC-SHA256
signing. Publishing cadence is accelerated for the demo; the power model uses
the real 30-second field duty cycle.
"""

from __future__ import annotations

import math
import random
import threading
import time
from datetime import datetime

from .config import Settings
from .crypto import derive_device_key, new_nonce
from .fleet import DeviceProfile
from .metrics import BatteryProfile
from .models import TelemetryReading, iso_z, utcnow


class VirtualVaccineNode:
    def __init__(
        self,
        profile: DeviceProfile,
        settings: Settings,
        interval_s: float | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.profile = profile
        self.settings = settings
        self.device_key = derive_device_key(settings.master_secret, profile.device_id)
        self.interval_s = interval_s or settings.node_interval_s
        self.battery = BatteryProfile(
            capacity_mah=settings.battery_capacity_mah,
            active_current_ma=settings.battery_active_ma,
            sleep_current_ma=settings.battery_sleep_ma,
            active_seconds=settings.battery_active_s,
            interval_seconds=settings.node_field_interval_s,
            derating=settings.battery_derating,
        )
        self._rng = rng or random.Random()
        self._lock = threading.RLock()
        self._seq = 0
        self._excursion = False
        self._started = time.monotonic()

    # ------------------------------------------------------------- simulation
    def set_excursion(self, active: bool) -> None:
        with self._lock:
            self._excursion = active

    @property
    def excursion_active(self) -> bool:
        with self._lock:
            return self._excursion

    def reset(self) -> None:
        with self._lock:
            self._seq = 0
            self._excursion = False
            self._started = time.monotonic()

    def set_seq(self, value: int) -> None:
        with self._lock:
            self._seq = max(0, int(value))

    def battery_pct(self) -> float:
        elapsed_h = (time.monotonic() - self._started) / 3600
        drained = elapsed_h * self.battery.average_current_ma / self.battery.capacity_mah * 100
        return max(3.0, min(100.0, self.profile.battery_start_pct - drained))

    def _position(self) -> tuple[int, int, int]:
        route = self.profile.route
        if not self.profile.moving or len(route) < 2:
            lat, lon = route[0]
            return (
                int(round((lat + self._rng.gauss(0, 0.00005)) * 1e7)),
                int(round((lon + self._rng.gauss(0, 0.00005)) * 1e7)),
                1,
            )
        # One full route takes roughly 40 simulated minutes.
        fraction = (self._seq * self.interval_s / 2400.0) % 1.0
        scaled = fraction * (len(route) - 1)
        segment = min(int(scaled), len(route) - 2)
        t = scaled - segment
        lat = route[segment][0] + (route[segment + 1][0] - route[segment][0]) * t
        lon = route[segment][1] + (route[segment + 1][1] - route[segment][1]) * t
        lat += self._rng.gauss(0, 0.00025)
        lon += self._rng.gauss(0, 0.00025)
        return int(round(lat * 1e7)), int(round(lon * 1e7)), 1

    def _temperature_centi(self) -> int:
        if self._excursion:
            value = self.profile.excursion_temp_c + self._rng.gauss(0, 0.12)
        else:
            phase = (self._seq * self.interval_s / 600.0) * 2 * math.pi
            value = (
                self.profile.base_temp_c
                + self.profile.temp_amplitude_c * math.sin(phase)
                + self._rng.gauss(0, 0.06)
            )
        return int(round(value * 100))

    def _humidity_milli(self) -> int:
        phase = (self._seq * self.interval_s / 900.0) * 2 * math.pi
        value = self.profile.humidity_pct + 1.8 * math.sin(phase) + self._rng.gauss(0, 0.35)
        return int(round(max(0.0, min(100.0, value)) * 1000))

    def read(self, now: datetime | None = None) -> TelemetryReading:
        with self._lock:
            moment = now or utcnow()
            lat_e7, lon_e7, gps_fix = self._position()
            reading = TelemetryReading(
                device_id=self.profile.device_id,
                seq=self._seq,
                measured_at=iso_z(moment),
                temperature_centi_c=self._temperature_centi(),
                humidity_milli_pct=self._humidity_milli(),
                lat_e7=lat_e7,
                lon_e7=lon_e7,
                gps_fix=gps_fix,
                nonce=new_nonce(),
                firmware=self.profile.firmware,
            )
            self._seq += 1
            return reading

    def envelope(self, now: datetime | None = None) -> dict:
        return self.read(now).envelope(self.device_key)


class NodeRunner(threading.Thread):
    """Publishes signed telemetry on a fixed cadence until stopped."""

    def __init__(
        self,
        node: VirtualVaccineNode,
        publish,
        topic_prefix: str = "vaccine",
        interval_s: float | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        super().__init__(name=f"node-{node.profile.device_id}", daemon=True)
        self.node = node
        self.publish = publish
        self.topic = f"{topic_prefix}/{node.profile.device_id}/telemetry"
        self.interval_s = interval_s or node.interval_s
        self.stop_event = stop_event or threading.Event()
        self.last_error: str | None = None
        self.published = 0

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                envelope = self.node.envelope()
                self.publish(self.topic, envelope)
                self.published += 1
                self.last_error = None
            except Exception as exc:  # keep the node alive across broker restarts
                self.last_error = f"{type(exc).__name__}: {exc}"
            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.05, self.interval_s - elapsed))

    def stop(self) -> None:
        self.stop_event.set()


def node_status(node: VirtualVaccineNode, last: dict | None) -> dict:
    profile = node.profile
    return {
        "id": profile.device_id,
        "name": profile.name,
        "transport": profile.transport,
        "route": [[round(lat, 5), round(lon, 5)] for lat, lon in profile.route],
        "firmware": profile.firmware,
        "battery_pct": round(node.battery_pct(), 1),
        "battery_runtime_h": round(node.battery.runtime_hours, 1),
        "excursion_active": node.excursion_active,
        "temperature_c": last["temperature_centi_c"] / 100 if last else None,
        "humidity_pct": last["humidity_milli_pct"] / 1000 if last else None,
        "lat": last["lat_e7"] / 1e7 if last else profile.route[0][0],
        "lon": last["lon_e7"] / 1e7 if last else profile.route[0][1],
        "last_seen": last["measured_at"] if last else None,
        "seq": last["seq"] if last else None,
    }
