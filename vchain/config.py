"""Runtime configuration, read from the environment with safe demo defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = REPO_ROOT / ".data" / "vchain.db"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    db_path: Path = DEFAULT_DB
    mqtt_host: str = "127.0.0.1"
    mqtt_port: int = 1883
    mqtt_topic: str = "vaccine/+/telemetry"
    api_host: str = "0.0.0.0"
    api_port: int = 12000

    block_size: int = 8
    block_interval_s: float = 1.0
    difficulty: int = 4
    validator_count: int = 3
    quorum: int = 2

    min_temp_c: float = 2.0
    max_temp_c: float = 8.0
    humidity_min_pct: float = 20.0
    humidity_max_pct: float = 80.0
    max_gap_s: int = 900
    max_future_skew_s: int = 300
    max_past_skew_s: int = 86400
    pending_timeout_s: int = 300

    master_secret: str = "dev-master-secret-change-me"
    node_interval_s: float = 2.0
    node_field_interval_s: float = 30.0
    battery_capacity_mah: float = 2500.0
    battery_active_ma: float = 120.0
    battery_sleep_ma: float = 0.05
    battery_active_s: float = 4.0
    battery_derating: float = 0.85

    seed_demo: bool = True
    start_nodes: bool = True
    log_level: str = "INFO"

    # Kept out of repr so it never lands in logs.
    extra: dict = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_env(cls) -> "Settings":
        base = cls()
        return replace(
            base,
            db_path=Path(os.environ.get("VCHAIN_DB_PATH", str(base.db_path))),
            mqtt_host=os.environ.get("VCHAIN_MQTT_HOST", base.mqtt_host),
            mqtt_port=_env_int("VCHAIN_MQTT_PORT", base.mqtt_port),
            mqtt_topic=os.environ.get("VCHAIN_MQTT_TOPIC", base.mqtt_topic),
            api_host=os.environ.get("VCHAIN_API_HOST", base.api_host),
            api_port=_env_int("VCHAIN_API_PORT", base.api_port),
            block_size=_env_int("VCHAIN_BLOCK_SIZE", base.block_size),
            block_interval_s=_env_float("VCHAIN_BLOCK_INTERVAL_S", base.block_interval_s),
            difficulty=_env_int("VCHAIN_DIFFICULTY", base.difficulty),
            validator_count=_env_int("VCHAIN_VALIDATORS", base.validator_count),
            quorum=_env_int("VCHAIN_QUORUM", base.quorum),
            min_temp_c=_env_float("VCHAIN_MIN_TEMP_C", base.min_temp_c),
            max_temp_c=_env_float("VCHAIN_MAX_TEMP_C", base.max_temp_c),
            master_secret=os.environ.get("VCHAIN_MASTER_SECRET", base.master_secret),
            node_interval_s=_env_float("VCHAIN_NODE_INTERVAL_S", base.node_interval_s),
            node_field_interval_s=_env_float("VCHAIN_NODE_FIELD_INTERVAL_S", base.node_field_interval_s),
            seed_demo=_env_bool("VCHAIN_SEED_DEMO", base.seed_demo),
            start_nodes=_env_bool("VCHAIN_START_NODES", base.start_nodes),
            log_level=os.environ.get("VCHAIN_LOG_LEVEL", base.log_level),
        )

    @property
    def policy(self) -> dict:
        return {
            "min_temp_centi_c": int(round(self.min_temp_c * 100)),
            "max_temp_centi_c": int(round(self.max_temp_c * 100)),
            "humidity_min_milli_pct": int(round(self.humidity_min_pct * 1000)),
            "humidity_max_milli_pct": int(round(self.humidity_max_pct * 1000)),
            "max_gap_s": self.max_gap_s,
            "max_future_skew_s": self.max_future_skew_s,
            "max_past_skew_s": self.max_past_skew_s,
        }
