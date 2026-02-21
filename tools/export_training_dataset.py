#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import random
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.feature_spec import FEATURE_ORDER, vectorize


KNOWN_TYPES = ["TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"]


def parse_csv_list(raw: str, upper: bool = True) -> List[str]:
    out = []
    for s in (raw or "").split(","):
        t = s.strip()
        if not t:
            continue
        t = t.upper() if upper else t.lower()
        if t not in out:
            out.append(t)
    return out


def parse_csv_set(raw: str, upper: bool = True) -> set:
    return set(parse_csv_list(raw, upper=upper))


def parse_features(raw: str) -> Optional[Dict]:
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def choose_label(
    row: sqlite3.Row,
    attack_types: set,
    attack_sources: set,
    benign_sources: set,
    benign_max_score: float,
    mode: str,
) -> Optional[str]:
    final_label = str(row["final_label"] or row["label"] or "").lower()
    decision_source = str(row["decision_source"] or "").lower()

    final_attack_type = str(row["final_attack_type"] or row["attack_type"] or "UNKNOWN").upper()
    rule_attack_type = str(row["rule_attack_type"] or row["attack_type"] or "UNKNOWN").upper()
    score = float(row["score"] or 0.0)

    if final_label == "attack":
        if decision_source in attack_sources:
            attack_type = final_attack_type if final_attack_type in attack_types else rule_attack_type
            if attack_type in attack_types:
                return attack_type if mode == "multiclass" else "ATTACK"
        return None

    if final_label == "benign":
        if decision_source in benign_sources and score <= benign_max_score:
            return "BENIGN"
        return None

    return None


def sample_balance(
    rows: List[Tuple[float, Dict, str]],
    benign_to_attack_ratio: float,
    seed: int,
) -> List[Tuple[float, Dict, str]]:
    benigns = [r for r in rows if r[2] == "BENIGN"]
    attacks = [r for r in rows if r[2] != "BENIGN"]
    if not attacks or not benigns:
        return rows

    max_benign = int(len(attacks) * benign_to_attack_ratio)
    if max_benign <= 0 or len(benigns) <= max_benign:
        return rows

    rng = random.Random(seed)
    selected_benign = rng.sample(benigns, max_benign)
    out = attacks + selected_benign
    out.sort(key=lambda x: x[0])
    return out


def build_chunks(n_rows: int, chunk_size: int) -> List[Dict]:
    if n_rows <= 0:
        return []
    # Keep multiple logical chunks for train/test split even on small datasets.
    target_chunk = max(100, int(np.ceil(n_rows / 8)))
    chunk_size = min(int(chunk_size), target_chunk) if int(chunk_size) > 0 else target_chunk
    chunks = []
    start = 0
    idx = 0
    while start < n_rows:
        end = min(start + chunk_size, n_rows)
        chunks.append({"path": f"online_chunk_{idx:04d}", "start": start, "end": end, "windows": end - start})
        start = end
        idx += 1
    return chunks


def main() -> None:
    ap = argparse.ArgumentParser(description="Export strict online events from SQLite into dl/data X.npy/y.npy")
    ap.add_argument("--db", default="logs/events.db")
    ap.add_argument("--table", default="events", choices=["events", "alerts"])
    ap.add_argument("--output-dir", default="dl/data")
    ap.add_argument("--mode", default="multiclass", choices=["multiclass", "binary"])
    ap.add_argument("--since-ts", type=float, default=0.0, help="Unix timestamp lower bound")
    ap.add_argument("--until-ts", type=float, default=0.0, help="Unix timestamp upper bound")
    ap.add_argument("--limit", type=int, default=0, help="Max rows scanned after filters")
    ap.add_argument("--attack-types", default="TCP_SYN_FLOOD,UDP_FLOOD,ICMP_FLOOD")
    ap.add_argument("--attack-sources", default="rules")
    ap.add_argument("--benign-sources", default="rules")
    ap.add_argument("--benign-max-score", type=float, default=0.0)
    ap.add_argument("--benign-to-attack-ratio", type=float, default=1.5)
    ap.add_argument("--chunk-size", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"db not found: {db_path}")

    attack_type_list = parse_csv_list(args.attack_types, upper=True)
    if not attack_type_list:
        attack_type_list = KNOWN_TYPES[:]
    attack_types = set(attack_type_list)
    attack_sources = parse_csv_set(args.attack_sources, upper=False)
    benign_sources = parse_csv_set(args.benign_sources, upper=False)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        sql = (
            f"SELECT ts,label,attack_type,final_label,final_attack_type,decision_source,rule_attack_type,score,features "
            f"FROM {args.table} WHERE features IS NOT NULL ORDER BY ts ASC"
        )
        params: List = []
        if args.since_ts > 0:
            sql = sql.replace("ORDER BY ts ASC", "AND ts >= ? ORDER BY ts ASC")
            params.append(float(args.since_ts))
        if args.until_ts > 0:
            sql = sql.replace("ORDER BY ts ASC", "AND ts <= ? ORDER BY ts ASC")
            params.append(float(args.until_ts))
        if args.limit > 0:
            sql += " LIMIT ?"
            params.append(int(args.limit))
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    selected: List[Tuple[float, Dict, str]] = []
    skipped_no_feat = 0
    skipped_label = 0

    for row in rows:
        features = parse_features(row["features"])
        if not features:
            skipped_no_feat += 1
            continue
        cls = choose_label(
            row=row,
            attack_types=attack_types,
            attack_sources=attack_sources,
            benign_sources=benign_sources,
            benign_max_score=float(args.benign_max_score),
            mode=str(args.mode),
        )
        if cls is None:
            skipped_label += 1
            continue
        selected.append((float(row["ts"] or 0.0), features, cls))

    if not selected:
        raise SystemExit("no rows selected; relax filters or verify DB has enough strict samples")

    selected = sample_balance(
        rows=selected,
        benign_to_attack_ratio=max(0.0, float(args.benign_to_attack_ratio)),
        seed=int(args.seed),
    )

    if args.mode == "binary":
        class_names = ["BENIGN", "ATTACK"]
    else:
        class_names = ["BENIGN"] + attack_type_list
    class_to_idx = {c: i for i, c in enumerate(class_names)}

    X = np.asarray([vectorize(feat) for _, feat, _ in selected], dtype=np.float32)
    y = np.asarray([class_to_idx.get(lbl, 0) for _, _, lbl in selected], dtype=np.int64)

    # strict sanity: need benign and at least one attack class
    class_counts = {name: int((y == idx).sum()) for idx, name in enumerate(class_names)}
    if class_counts.get("BENIGN", 0) == 0:
        raise SystemExit("no BENIGN selected; check benign filters")
    if sum(v for k, v in class_counts.items() if k != "BENIGN") == 0:
        raise SystemExit("no ATTACK class selected; check attack filters")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_dir / "X.npy", X)
    np.save(out_dir / "y.npy", y)

    chunks = build_chunks(len(selected), max(100, int(args.chunk_size)))
    for c in chunks:
        s, e = c["start"], c["end"]
        yy = y[s:e]
        c["class_counts"] = {name: int((yy == idx).sum()) for idx, name in enumerate(class_names)}

    meta = {
        "feature_order": FEATURE_ORDER,
        "class_names": class_names,
        "label_mode": args.mode,
        "source": {
            "db": str(db_path),
            "table": args.table,
            "since_ts": float(args.since_ts),
            "until_ts": float(args.until_ts),
            "attack_types": attack_type_list,
            "attack_sources": sorted(list(attack_sources)),
            "benign_sources": sorted(list(benign_sources)),
            "benign_max_score": float(args.benign_max_score),
            "benign_to_attack_ratio": float(args.benign_to_attack_ratio),
        },
        "total_windows": int(len(y)),
        "class_counts": class_counts,
        "skipped_no_feat": int(skipped_no_feat),
        "skipped_label": int(skipped_label),
        "files": chunks,
    }
    with open(out_dir / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"[ok] saved -> {out_dir / 'X.npy'} shape={X.shape}")
    print(f"[ok] saved -> {out_dir / 'y.npy'}")
    print(f"[ok] class_counts={class_counts}")
    print(f"[ok] saved -> {out_dir / 'meta.json'}")
    print(f"[info] scanned={len(rows)} selected={len(selected)} skipped_no_feat={skipped_no_feat} skipped_label={skipped_label}")


if __name__ == "__main__":
    main()
