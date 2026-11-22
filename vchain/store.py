"""SQLite persistence for readings, blocks, alerts, audits and tamper events.

The ledger tables are append-only by convention; the tamper lab deliberately
violates that convention to prove the audit engine notices.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

from .models import iso_z, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    difficulty INTEGER NOT NULL,
    reading_count INTEGER NOT NULL,
    digests_json TEXT NOT NULL,
    alert_digests_json TEXT NOT NULL,
    excursion_count INTEGER NOT NULL,
    policy_json TEXT NOT NULL,
    validator_sigs_json TEXT NOT NULL,
    mine_ms REAL NOT NULL DEFAULT 0,
    synthetic INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS readings (
    digest TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    measured_at TEXT NOT NULL,
    temperature_centi_c INTEGER NOT NULL,
    humidity_milli_pct INTEGER NOT NULL,
    lat_e7 INTEGER NOT NULL,
    lon_e7 INTEGER NOT NULL,
    gps_fix INTEGER NOT NULL,
    firmware TEXT NOT NULL,
    nonce TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    received_at TEXT NOT NULL,
    anchored_at TEXT,
    block_index INTEGER,
    status TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'mqtt',
    latency_ms REAL,
    rule_violations_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_readings_device ON readings(device_id, measured_at);
CREATE INDEX IF NOT EXISTS idx_readings_status ON readings(status, received_at);
CREATE INDEX IF NOT EXISTS idx_readings_block ON readings(block_index);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    device_id TEXT NOT NULL,
    reading_digest TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    block_index INTEGER,
    alert_digest TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_alerts_digest ON alerts(reading_digest);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS device_state (
    device_id TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    ok INTEGER NOT NULL,
    checks INTEGER NOT NULL,
    readings_checked INTEGER NOT NULL,
    blocks_checked INTEGER NOT NULL,
    alerts_checked INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    failures_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tamper_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL,
    detected INTEGER NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0,
    failures_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

BLOCK_MUTABLE_COLUMNS = {
    "hash",
    "prev_hash",
    "merkle_root",
    "digests_json",
    "alert_digests_json",
    "reading_count",
    "excursion_count",
    "nonce",
    "created_at",
}

READING_MUTABLE_COLUMNS = {
    "temperature_centi_c",
    "humidity_milli_pct",
    "lat_e7",
    "lon_e7",
    "gps_fix",
    "payload_json",
    "signature",
    "status",
    "block_index",
    "anchored_at",
    "latency_ms",
    "source",
    "received_at",
    "measured_at",
    "seq",
    "digest",
}


class ChainStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._revision = 0
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=15)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    # ------------------------------------------------------------------ setup
    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)

    @property
    def revision(self) -> int:
        return self._revision

    def reset(self) -> None:
        with self._lock, self._conn:
            self._revision += 1
            for table in (
                "blocks",
                "readings",
                "alerts",
                "device_state",
                "audit_runs",
                "tamper_events",
                "meta",
            ):
                self._conn.execute(f"DROP TABLE IF EXISTS {table}")
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    # ----------------------------------------------------------------- blocks
    def insert_block(self, row: dict) -> None:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._lock, self._conn:
            self._revision += 1
            self._conn.execute(
                f"INSERT INTO blocks ({columns}) VALUES ({placeholders})", tuple(row.values())
            )

    def get_block(self, index: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM blocks WHERE idx=?", (index,)).fetchone()
        return dict(row) if row else None

    def latest_block(self) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def mutate_block(self, index: int, updates: dict) -> bool:
        unknown = set(updates) - BLOCK_MUTABLE_COLUMNS
        if unknown:
            raise ValueError(f"refusing to mutate unknown block columns: {sorted(unknown)}")
        assignments = ", ".join(f"{column}=?" for column in updates)
        with self._lock, self._conn:
            self._revision += 1
            cursor = self._conn.execute(
                f"UPDATE blocks SET {assignments} WHERE idx=?", (*updates.values(), index)
            )
        return cursor.rowcount > 0

    def all_blocks(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM blocks ORDER BY idx ASC").fetchall()
        return [dict(r) for r in rows]

    def block_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM blocks").fetchone()
        return int(row["n"])

    # --------------------------------------------------------------- readings
    def insert_reading(self, row: dict) -> bool:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._lock, self._conn:
            self._revision += 1
            cursor = self._conn.execute(
                f"INSERT OR IGNORE INTO readings ({columns}) VALUES ({placeholders})",
                tuple(row.values()),
            )
        return cursor.rowcount > 0

    def get_reading(self, digest: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM readings WHERE digest=?", (digest,)).fetchone()
        return dict(row) if row else None

    def reading_exists(self, digest: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM readings WHERE digest=?", (digest,)).fetchone()
        return row is not None

    def pending_readings(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM readings WHERE status='pending' ORDER BY received_at ASC, rowid ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM readings WHERE status='pending'").fetchone()
        return int(row["n"])

    def mark_anchored(self, entries: list[tuple[str, int, str, float]]) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE readings SET status='anchored', block_index=?, anchored_at=?, latency_ms=? WHERE digest=?",
                [(block_index, anchored_at, latency, digest) for digest, block_index, anchored_at, latency in entries],
            )

    def list_readings(
        self, limit: int = 50, device_id: str | None = None, status: str | None = None
    ) -> list[dict]:
        query = "SELECT * FROM readings"
        clauses: list[str] = []
        params: list[Any] = []
        if device_id:
            clauses.append("device_id=?")
            params.append(device_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY received_at DESC, rowid DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def all_readings(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM readings ORDER BY rowid ASC").fetchall()
        return [dict(r) for r in rows]

    def readings_for_block(self, block_index: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM readings WHERE block_index=? ORDER BY rowid ASC", (block_index,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_reading(self, digest: str) -> bool:
        with self._lock, self._conn:
            self._revision += 1
            cursor = self._conn.execute("DELETE FROM readings WHERE digest=?", (digest,))
        return cursor.rowcount > 0

    def mutate_reading(self, digest: str, updates: dict) -> bool:
        unknown = set(updates) - READING_MUTABLE_COLUMNS
        if unknown:
            raise ValueError(f"refusing to mutate unknown columns: {sorted(unknown)}")
        assignments = ", ".join(f"{column}=?" for column in updates)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"UPDATE readings SET {assignments} WHERE digest=?",
                (*updates.values(), digest),
            )
        return cursor.rowcount > 0

    def last_seq(self, device_id: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_seq FROM device_state WHERE device_id=?", (device_id,)
            ).fetchone()
            if row:
                return int(row["last_seq"])
            fallback = self._conn.execute(
                "SELECT MAX(seq) AS m FROM readings WHERE device_id=? AND status!='rejected'",
                (device_id,),
            ).fetchone()
        return int(fallback["m"]) if fallback and fallback["m"] is not None else None

    def set_device_state(self, device_id: str, last_seq: int, last_seen: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO device_state(device_id, last_seq, last_seen) VALUES(?,?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET last_seq=excluded.last_seq, last_seen=excluded.last_seen",
                (device_id, last_seq, last_seen),
            )

    def latency_values(self, limit: int = 400) -> list[float]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT latency_ms FROM readings "
                "WHERE status='anchored' AND source='mqtt' AND latency_ms IS NOT NULL "
                "ORDER BY anchored_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [float(r["latency_ms"]) for r in rows]

    def readings_since(self, since: str, limit: int = 2000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM readings WHERE received_at >= ? ORDER BY received_at ASC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def device_last_readings(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ("
                "  SELECT r.*, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY measured_at DESC, rowid DESC) AS rn"
                "  FROM readings r WHERE status='anchored'"
                ") WHERE rn=1"
            ).fetchall()
        return {row["device_id"]: dict(row) for row in rows}

    def temperature_history(self, per_device: int = 40) -> dict[str, list[dict]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ("
                "  SELECT r.digest, r.device_id, r.measured_at, r.temperature_centi_c, r.block_index,"
                "         ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY measured_at DESC, rowid DESC) AS rn"
                "  FROM readings r WHERE status='anchored'"
                ") WHERE rn <= ? ORDER BY measured_at ASC",
                (per_device,),
            ).fetchall()
        series: dict[str, list[dict]] = {}
        for row in rows:
            series.setdefault(row["device_id"], []).append(
                {
                    "measured_at": row["measured_at"],
                    "temperature_c": row["temperature_centi_c"] / 100,
                    "block_index": row["block_index"],
                }
            )
        return series

    def device_temperatures(self, device_id: str, limit: int = 240) -> list[float]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT temperature_centi_c FROM readings WHERE device_id=? AND status='anchored' "
                "ORDER BY measured_at DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        return [r["temperature_centi_c"] / 100 for r in rows]

    def device_readings_count(self, device_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM readings WHERE device_id=? AND status='anchored'",
                (device_id,),
            ).fetchone()
        return int(row["n"])

    # ----------------------------------------------------------------- alerts
    def insert_alert(self, row: dict) -> bool:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"INSERT OR IGNORE INTO alerts ({columns}) VALUES ({placeholders})",
                tuple(row.values()),
            )
        return cursor.rowcount > 0

    def alerts_for_digests(self, digests: list[str]) -> list[dict]:
        if not digests:
            return []
        marks = ", ".join("?" for _ in digests)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM alerts WHERE reading_digest IN ({marks}) AND block_index IS NULL",
                tuple(digests),
            ).fetchall()
        return [dict(r) for r in rows]

    def set_alerts_block(self, alert_digests: list[str], block_index: int) -> None:
        if not alert_digests:
            return
        marks = ", ".join("?" for _ in alert_digests)
        with self._lock, self._conn:
            self._conn.execute(
                f"UPDATE alerts SET block_index=? WHERE alert_digest IN ({marks})",
                (block_index, *alert_digests),
            )

    def list_alerts(self, limit: int = 50, since_id: int | None = None) -> list[dict]:
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        if since_id is not None:
            query += " WHERE id > ?"
            params.append(since_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def all_alerts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

    def alert_counts(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
            critical = self._conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE severity='critical'"
            ).fetchone()["n"]
            excursions = self._conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE kind IN ('TEMPERATURE_HIGH','TEMPERATURE_LOW')"
            ).fetchone()["n"]
        return {"total": int(total), "critical": int(critical), "excursions": int(excursions)}

    def alert_counts_by_device(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT device_id, kind, severity, COUNT(*) AS n FROM alerts GROUP BY device_id, kind, severity"
            ).fetchall()
        summary: dict[str, dict] = {}
        for row in rows:
            entry = summary.setdefault(row["device_id"], {"excursions": 0, "warnings": 0, "info": 0})
            if row["kind"] in ("TEMPERATURE_HIGH", "TEMPERATURE_LOW"):
                entry["excursions"] += int(row["n"])
            elif row["severity"] == "warning":
                entry["warnings"] += int(row["n"])
            else:
                entry["info"] += int(row["n"])
        return summary

    # ------------------------------------------------------------------ audit
    def insert_audit(self, row: dict) -> int:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"INSERT INTO audit_runs ({columns}) VALUES ({placeholders})", tuple(row.values())
            )
        return int(cursor.lastrowid)

    def latest_audit(self) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM audit_runs ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def audit_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM audit_runs").fetchone()
        return int(row["n"])

    # ------------------------------------------------------------------ tamper
    def insert_tamper_event(self, row: dict) -> int:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"INSERT INTO tamper_events ({columns}) VALUES ({placeholders})", tuple(row.values())
            )
        return int(cursor.lastrowid)

    def tamper_stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total, COALESCE(SUM(detected), 0) AS detected FROM tamper_events"
            ).fetchone()
        return {"total": int(row["total"]), "detected": int(row["detected"])}

    def list_tamper_events(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tamper_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ stats
    def counts(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT "
                " COUNT(*) AS total,"
                " COALESCE(SUM(status='anchored'), 0) AS anchored,"
                " COALESCE(SUM(status='pending'), 0) AS pending,"
                " COALESCE(SUM(status='rejected'), 0) AS rejected,"
                " COALESCE(SUM(source='mqtt'), 0) AS live"
                " FROM readings"
            ).fetchone()
            blocks = self._conn.execute("SELECT COALESCE(MAX(idx), 0) AS h FROM blocks").fetchone()["h"]
            anchored_since = iso_z(utcnow() - timedelta(minutes=1))
            per_minute = self._conn.execute(
                "SELECT COUNT(*) AS n FROM readings WHERE received_at >= ? AND source='mqtt'",
                (anchored_since,),
            ).fetchone()["n"]
        return {
            "readings_total": int(row["total"]),
            "readings_anchored": int(row["anchored"]),
            "readings_pending": int(row["pending"]),
            "readings_rejected": int(row["rejected"]),
            "readings_live": int(row["live"]),
            "chain_height": int(blocks),
            "throughput_per_min": int(per_minute),
        }
