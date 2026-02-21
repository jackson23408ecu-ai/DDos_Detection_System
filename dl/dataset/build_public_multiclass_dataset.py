#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

import numpy as np
import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.build_window_dataset import process_file
from dl.dataset.feature_spec import FEATURE_ORDER, vectorize


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def map_public_type(raw_attack_type: str, file_path: Path, mode: str = "full") -> str:
    s = f"{str(raw_attack_type or '').upper()} {file_path.stem.upper()}"
    if "BENIGN" in s or "NORMAL" in s:
        return "BENIGN"

    # Core classes used online.
    if "SYN" in s:
        return "TCP_SYN_FLOOD"
    if "ICMP" in s or "PING" in s:
        return "ICMP_FLOOD"

    # Optional expanded classes for demo candidates.
    if mode == "full":
        if "DNS" in s:
            return "DNS_AMP_FLOOD"
        if "NTP" in s:
            return "NTP_AMP_FLOOD"
        if "LDAP" in s:
            return "LDAP_AMP_FLOOD"
        if "MSSQL" in s:
            return "MSSQL_AMP_FLOOD"
        if "NETBIOS" in s:
            return "NETBIOS_AMP_FLOOD"
        if "PORTMAP" in s:
            return "PORTMAP_AMP_FLOOD"
        if "SNMP" in s:
            return "SNMP_AMP_FLOOD"
        if "TFTP" in s:
            return "TFTP_FLOOD"
        if "UDPLAG" in s:
            return "UDP_LAG_FLOOD"

    # UDP-like fallback.
    if "UDP" in s or "DRDOS" in s:
        return "UDP_FLOOD"
    return "UDP_FLOOD"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="dl/config.yaml")
    ap.add_argument("--output-dir", default="dl/data_public")
    ap.add_argument("--mode", default="full", choices=["full", "basic4"])
    ap.add_argument("--sample-per-file", type=int, default=-1)
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    ds_cfg = cfg.get("dataset", {}) or {}
    input_glob = ds_cfg.get("input_glob", "data/archive/*.parquet")
    window_sec = float(ds_cfg.get("window_sec", 1.0))
    min_flows = int(ds_cfg.get("min_flows_per_window", 1))
    label_col = str(ds_cfg.get("label_col", "Label"))
    ts_cols = ds_cfg.get("timestamp_cols", ["Timestamp"]) or ["Timestamp"]
    sample_cfg = int(ds_cfg.get("sample_per_file", 0))
    sample = sample_cfg if args.sample_per_file < 0 else int(args.sample_per_file)

    pattern = input_glob
    if not Path(pattern).is_absolute():
        pattern = str(ROOT / pattern)
    files = [Path(p) for p in sorted(glob.glob(pattern))]
    if not files:
        raise SystemExit(f"no parquet files matched: {input_glob}")

    X_list = []
    y_name = []
    file_meta = []
    idx = 0

    for path in files:
        windows, _, attack_types = process_file(
            path=path,
            window_sec=window_sec,
            min_flows=min_flows,
            label_col=label_col,
            ts_cols=ts_cols,
            sample=sample,
        )
        if not windows:
            continue

        start = idx
        local_labels = []
        for feat, raw_type in zip(windows, attack_types):
            cls = map_public_type(raw_type, path, mode=args.mode)
            if args.mode == "basic4":
                if cls not in ("BENIGN", "TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"):
                    cls = "UDP_FLOOD"
            X_list.append(vectorize(feat))
            y_name.append(cls)
            local_labels.append(cls)
        idx = len(X_list)
        file_meta.append(
            {
                "path": str(path),
                "start": start,
                "end": idx,
                "windows": idx - start,
                "class_counts": dict(Counter(local_labels)),
            }
        )

    if not X_list:
        raise SystemExit("empty public dataset")

    # BENIGN first, then fixed common classes, then remaining.
    fixed = ["BENIGN", "TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"]
    observed = list(dict.fromkeys(y_name))
    class_names = [c for c in fixed if c in observed]
    class_names.extend([c for c in observed if c not in class_names])
    class_to_idx = {c: i for i, c in enumerate(class_names)}

    X = np.asarray(X_list, dtype=np.float32)
    y = np.asarray([class_to_idx[c] for c in y_name], dtype=np.int64)

    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_dir / "X.npy", X)
    np.save(out_dir / "y.npy", y)

    meta = {
        "feature_order": FEATURE_ORDER,
        "class_names": class_names,
        "source": {"input_glob": input_glob, "mode": args.mode, "sample_per_file": sample},
        "total_windows": int(len(y)),
        "class_counts": {name: int((y == idx).sum()) for idx, name in enumerate(class_names)},
        "files": file_meta,
    }
    with open(out_dir / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"[ok] saved -> {out_dir / 'X.npy'} shape={X.shape}")
    print(f"[ok] saved -> {out_dir / 'y.npy'} shape={y.shape}")
    print(f"[ok] class_names={class_names}")
    print(f"[ok] class_counts={meta['class_counts']}")
    print(f"[ok] saved -> {out_dir / 'meta.json'}")


if __name__ == "__main__":
    main()
