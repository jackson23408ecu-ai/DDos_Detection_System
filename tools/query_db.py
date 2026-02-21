#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sqlite3
from pathlib import Path


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="logs/events.db")
    ap.add_argument("--tail", type=int, default=0, help="show last N events")
    ap.add_argument("--alerts", action="store_true", help="query alerts table for --tail")
    ap.add_argument("--count", action="store_true", help="show total counts")
    ap.add_argument("--stats", action="store_true", help="show recent label/attack_type summary")
    ap.add_argument("--sql", default="", help="run custom SQL and print rows")
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"db not found: {db_path}")

    conn = connect(db_path)
    try:
        if args.count:
            ev = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            al = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            print(f"events: {ev}")
            print(f"alerts: {al}")

        if args.stats:
            rows = conn.execute(
                "SELECT label, attack_type, COUNT(*) AS c FROM events GROUP BY label, attack_type ORDER BY c DESC LIMIT 20"
            ).fetchall()
            for r in rows:
                print(f"{r['label']}\t{r['attack_type']}\t{r['c']}")

        if args.tail > 0:
            table = "alerts" if args.alerts else "events"
            rows = conn.execute(
                f"SELECT ts,label,attack_type,score,confidence FROM {table} ORDER BY ts DESC LIMIT ?",
                (args.tail,),
            ).fetchall()
            for r in rows:
                print(f"{r['ts']}\t{r['label']}\t{r['attack_type']}\t{r['score']}\t{r['confidence']}")

        if args.sql:
            rows = conn.execute(args.sql).fetchall()
            for r in rows:
                print(dict(r))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
