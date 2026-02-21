#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import random
import sqlite3
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,
  label TEXT,
  attack_type TEXT,
  final_label TEXT,
  final_attack_type TEXT,
  decision_source TEXT,
  dl_p_attack REAL,
  dl_model_version TEXT,
  dl_error TEXT,
  dl_type_probs TEXT,
  dl_extra_type TEXT,
  dl_extra_confidence REAL,
  rule_label TEXT,
  rule_attack_type TEXT,
  score REAL,
  confidence REAL,
  reasons TEXT,
  features TEXT,
  pps REAL,
  bps REAL,
  uniq_src INTEGER,
  uniq_flow5 INTEGER,
  syn_ratio REAL,
  syn_only_ratio REAL,
  top_src_ip TEXT,
  top_dport TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,
  label TEXT,
  attack_type TEXT,
  final_label TEXT,
  final_attack_type TEXT,
  decision_source TEXT,
  dl_p_attack REAL,
  dl_model_version TEXT,
  dl_error TEXT,
  dl_type_probs TEXT,
  dl_extra_type TEXT,
  dl_extra_confidence REAL,
  rule_label TEXT,
  rule_attack_type TEXT,
  score REAL,
  confidence REAL,
  reasons TEXT,
  features TEXT,
  pps REAL,
  bps REAL,
  uniq_src INTEGER,
  uniq_flow5 INTEGER,
  syn_ratio REAL,
  syn_only_ratio REAL,
  top_src_ip TEXT,
  top_dport TEXT
);
CREATE TABLE IF NOT EXISTS ingest_state (
  file_path TEXT PRIMARY KEY,
  offset INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_label ON events(label);
CREATE INDEX IF NOT EXISTS idx_events_attack ON events(attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""

EXTRA_COLUMNS = [
    ("final_label", "final_label TEXT"),
    ("final_attack_type", "final_attack_type TEXT"),
    ("decision_source", "decision_source TEXT"),
    ("dl_p_attack", "dl_p_attack REAL"),
    ("dl_model_version", "dl_model_version TEXT"),
    ("dl_error", "dl_error TEXT"),
    ("dl_type_probs", "dl_type_probs TEXT"),
    ("dl_extra_type", "dl_extra_type TEXT"),
    ("dl_extra_confidence", "dl_extra_confidence REAL"),
    ("rule_label", "rule_label TEXT"),
    ("rule_attack_type", "rule_attack_type TEXT"),
]


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.executescript(SCHEMA)
    ensure_columns(conn, "events", EXTRA_COLUMNS)
    ensure_columns(conn, "alerts", EXTRA_COLUMNS)
    return conn


def ensure_columns(conn: sqlite3.Connection, table: str, columns):
    cur = conn.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    for name, decl in columns:
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {decl}")


def _safe_get(d, path, default=None):
    cur = d
    try:
        for k in path.split("."):
            cur = cur.get(k)
        return cur if cur is not None else default
    except Exception:
        return default


def read_offset(conn: sqlite3.Connection, file_path: str) -> int:
    cur = conn.execute("SELECT offset FROM ingest_state WHERE file_path=?", (file_path,))
    row = cur.fetchone()
    if row:
        return int(row[0] or 0)
    return 0


def write_offset(conn: sqlite3.Connection, file_path: str, offset: int) -> None:
    conn.execute(
        "INSERT INTO ingest_state(file_path, offset) VALUES(?, ?) "
        "ON CONFLICT(file_path) DO UPDATE SET offset=excluded.offset",
        (file_path, offset),
    )


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except Exception:
        return None


def build_row(obj: dict) -> tuple:
    features = obj.get("features", {}) or {}
    reasons = obj.get("reasons", [])

    pps = _safe_get(features, "pps", 0)
    bps = _safe_get(features, "bps", 0)
    uniq_src = _safe_get(features, "uniq_src", 0)
    uniq_flow5 = _safe_get(features, "uniq_flow5", 0)
    syn_ratio = _safe_get(features, "syn_ratio", 0)
    syn_only_ratio = _safe_get(features, "syn_only_ratio", 0)
    top_src = _safe_get(features, "top_src_ip", [])
    top_dport = _safe_get(features, "top_dport", [])

    final_label = obj.get("final_label", obj.get("label", "unknown"))
    final_attack_type = obj.get("final_attack_type", obj.get("attack_type", "UNKNOWN"))
    decision_source = obj.get("decision_source", "rules")
    dl_p_attack = obj.get("dl_p_attack", None)
    try:
        dl_p_attack = float(dl_p_attack) if dl_p_attack is not None else None
    except Exception:
        dl_p_attack = None
    dl_model_version = obj.get("dl_model_version", None)
    dl_error = obj.get("dl_error", None)
    dl_type_probs = obj.get("dl_type_probs", None)
    if not isinstance(dl_type_probs, dict):
        dl_type_probs = None
    dl_extra_type = obj.get("dl_extra_type", None)
    dl_extra_confidence = obj.get("dl_extra_confidence", None)
    try:
        dl_extra_confidence = float(dl_extra_confidence) if dl_extra_confidence is not None else None
    except Exception:
        dl_extra_confidence = None
    rule_label = obj.get("rule_label", obj.get("label", "unknown"))
    rule_attack_type = obj.get("rule_attack_type", obj.get("attack_type", "UNKNOWN"))

    return (
        obj.get("ts", time.time()),
        obj.get("label", "unknown"),
        obj.get("attack_type", "UNKNOWN"),
        final_label,
        final_attack_type,
        decision_source,
        dl_p_attack,
        dl_model_version,
        dl_error,
        (json.dumps(dl_type_probs, ensure_ascii=False) if dl_type_probs is not None else None),
        dl_extra_type,
        dl_extra_confidence,
        rule_label,
        rule_attack_type,
        obj.get("score", 0),
        obj.get("confidence", 0.0),
        json.dumps(reasons, ensure_ascii=False),
        json.dumps(features, ensure_ascii=False),
        pps,
        bps,
        int(uniq_src or 0),
        int(uniq_flow5 or 0),
        float(syn_ratio or 0),
        float(syn_only_ratio or 0),
        json.dumps(top_src, ensure_ascii=False),
        json.dumps(top_dport, ensure_ascii=False),
    )


def ingest_file(
    conn: sqlite3.Connection,
    file_path: Path,
    table: str,
    benign_sample_rate: float = 1.0,
    rng: random.Random | None = None,
) -> int:
    file_path = file_path.resolve()
    if not file_path.exists():
        return 0

    offset = read_offset(conn, str(file_path))
    try:
        size = file_path.stat().st_size
    except Exception:
        size = 0

    if size < offset:
        offset = 0

    rows = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)
        for line in f:
            obj = parse_line(line)
            if not obj:
                continue
            if table == "events" and benign_sample_rate < 1.0:
                label = str(obj.get("final_label", obj.get("label", "unknown"))).lower()
                if label == "benign":
                    r = rng.random() if rng else random.random()
                    if r > benign_sample_rate:
                        continue
            rows.append(build_row(obj))
        offset = f.tell()

    if rows:
        conn.executemany(
            f"INSERT INTO {table} (ts,label,attack_type,final_label,final_attack_type,decision_source,dl_p_attack,dl_model_version,dl_error,dl_type_probs,dl_extra_type,dl_extra_confidence,rule_label,rule_attack_type,score,confidence,reasons,features,pps,bps,uniq_src,uniq_flow5,syn_ratio,syn_only_ratio,top_src_ip,top_dport) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    write_offset(conn, str(file_path), offset)
    conn.commit()
    return len(rows)


def cleanup_events(conn: sqlite3.Connection, retention_sec: float) -> int:
    if retention_sec <= 0:
        return 0
    cutoff = time.time() - retention_sec
    cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount or 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="logs/events.db")
    ap.add_argument("--events", default="logs/events.jsonl")
    ap.add_argument("--alerts", default="logs/alerts.jsonl")
    ap.add_argument("--poll", type=float, default=0.2)
    ap.add_argument("--events-retention-hours", type=float, default=168.0, help="events table retention in hours (0=disable)")
    ap.add_argument("--cleanup-interval", type=float, default=300.0, help="cleanup interval in seconds")
    ap.add_argument("--benign-sample-rate", type=float, default=1.0, help="sample rate for benign events (0-1)")
    ap.add_argument("--sample-seed", type=int, default=42)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = connect(db_path)
    events_path = Path(args.events)
    alerts_path = Path(args.alerts)
    rng = random.Random(args.sample_seed)

    retention_sec = max(0.0, float(args.events_retention_hours)) * 3600.0
    cleanup_interval = max(1.0, float(args.cleanup_interval))
    last_cleanup = 0.0

    while True:
        ingested = 0
        ingested += ingest_file(
            conn,
            events_path,
            "events",
            benign_sample_rate=float(max(0.0, min(1.0, args.benign_sample_rate))),
            rng=rng,
        )
        ingested += ingest_file(conn, alerts_path, "alerts")

        now = time.time()
        if retention_sec > 0 and (args.once or now - last_cleanup >= cleanup_interval):
            cleanup_events(conn, retention_sec)
            last_cleanup = now

        if args.once:
            break
        time.sleep(args.poll)

    conn.close()


if __name__ == "__main__":
    main()
