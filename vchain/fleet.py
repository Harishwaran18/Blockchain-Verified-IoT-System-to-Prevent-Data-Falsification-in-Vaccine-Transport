"""Fleet definitions: routes, device identities and simulated sensor profiles."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    name: str
    route: list[tuple[float, float]]  # (lat, lon) waypoints
    transport: str
    firmware: str = "1.0.0"
    base_temp_c: float = 5.0
    temp_amplitude_c: float = 0.35
    humidity_pct: float = 45.0
    battery_start_pct: float = 98.0
    moving: bool = True
    # Temperature the node reports while an excursion is active.
    excursion_temp_c: float = 9.4
    meta: dict = field(default_factory=dict)


DEVICES: list[DeviceProfile] = [
    DeviceProfile(
        device_id="VX-001",
        name="Truck A · Nairobi → Mombasa",
        route=[
            (-1.2921, 36.8219),
            (-1.8500, 37.3000),
            (-2.7000, 38.0000),
            (-3.5000, 38.6000),
            (-4.0435, 39.6682),
        ],
        transport="road",
        base_temp_c=5.1,
        humidity_pct=46.0,
    ),
    DeviceProfile(
        device_id="VX-002",
        name="Truck B · Mombasa → Nairobi",
        route=[
            (-4.0435, 39.6682),
            (-3.2000, 38.4000),
            (-2.3000, 37.6000),
            (-1.6000, 37.1000),
            (-1.2921, 36.8219),
        ],
        transport="road",
        base_temp_c=4.7,
        humidity_pct=51.0,
        battery_start_pct=93.0,
    ),
    DeviceProfile(
        device_id="VX-003",
        name="Cold Room · Nairobi Depot",
        route=[(-1.3187, 36.8890), (-1.3189, 36.8892)],
        transport="stationary",
        base_temp_c=4.2,
        temp_amplitude_c=0.15,
        humidity_pct=42.0,
        battery_start_pct=100.0,
        moving=False,
    ),
    DeviceProfile(
        device_id="VX-004",
        name="Truck C · Kisumu → Eldoret",
        route=[
            (-0.0917, 34.7680),
            (0.1000, 34.9000),
            (0.2827, 35.0000),
            (0.5143, 35.2698),
        ],
        transport="road",
        base_temp_c=5.6,
        humidity_pct=48.0,
        battery_start_pct=88.0,
    ),
]

DEVICE_BY_ID = {d.device_id: d for d in DEVICES}
