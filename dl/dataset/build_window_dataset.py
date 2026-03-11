#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.dataset.feature_spec import FEATURE_ORDER, enrich_temporal_features, vectorize


BENIGN_LABELS = {
    "benign",
    "normal",
    "benigntraffic",
    "benign traffic",
}


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _safe_col(df: pd.DataFrame, names: List[str], default=0):
    for name in names:
        if name in df.columns:
            return df[name].fillna(default)
    return pd.Series([default] * len(df), index=df.index)


def _parse_timestamp(df: pd.DataFrame, cols: List[str]) -> pd.Series:
    for name in cols:
        if name in df.columns:
            col = df[name]
            if pd.api.types.is_numeric_dtype(col):
                arr = pd.to_numeric(col, errors="coerce").fillna(0).astype(float)
                max_v = float(arr.max() or 0)
                # Heuristic: ns > 1e12, ms > 1e10
                if max_v > 1e12:
                    return arr / 1e9
                if max_v > 1e10:
                    return arr / 1e3
                return arr
            ts = pd.to_datetime(col, errors="coerce", infer_datetime_format=True)
            ts = ts.fillna(pd.Timestamp("1970-01-01"))
            return ts.astype("int64") / 1e9
    # fallback: use index as seconds
    return pd.Series(np.arange(len(df), dtype=np.float64), index=df.index)


def _normalize_label(raw) -> str:
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    if s in BENIGN_LABELS:
        return "benign"
    return "attack"


def _entropy_from_counts(counts: np.ndarray) -> float:
    total = float(counts.sum())
    if total <= 0:
        return 0.0
    probs = counts / total
    return float(-(probs * np.log2(probs + 1e-12)).sum())


def _agg_packet_len(group: pd.DataFrame) -> Tuple[float, float]:
    weights = group["total_pkts"].to_numpy(dtype=np.float64)
    total = float(weights.sum())
    if total <= 0:
        return 0.0, 0.0
    means = group["pktlen_mean"].to_numpy(dtype=np.float64)
    vars_ = group["pktlen_var"].to_numpy(dtype=np.float64)
    mean = float((means * weights).sum() / total)
    var = float((weights * (vars_ + (means - mean) ** 2)).sum() / total)
    return mean, var


def build_windows(df: pd.DataFrame, window_sec: float, min_flows: int) -> Tuple[List[Dict], List[int], List[str]]:
    ts_sec = df["ts_sec"].to_numpy(dtype=np.float64)
    window_id = (ts_sec // window_sec).astype(np.int64)
    df = df.copy()
    df["window_id"] = window_id

    windows = []
    labels = []
    attack_types = []

    for win, group in df.groupby("window_id", sort=True):
        if len(group) < min_flows:
            continue

        pkt_cnt = float(group["total_pkts"].sum())
        byte_cnt = float(group["total_bytes"].sum())
        pps = pkt_cnt / max(window_sec, 1e-6)
        bps = byte_cnt / max(window_sec, 1e-6)

        uniq_src = int(group["src_ip"].nunique())
        uniq_dst = int(group["dst_ip"].nunique())
        uniq_pair = int(group["pair_key"].nunique())
        uniq_flow5 = int(group["flow5_key"].nunique())

        avg_pkts_per_src = pkt_cnt / uniq_src if uniq_src else 0.0
        avg_pkts_per_dst = pkt_cnt / uniq_dst if uniq_dst else 0.0

        # entropy (weighted by packets)
        src_counts = group.groupby("src_ip")["total_pkts"].sum().to_numpy(dtype=np.float64)
        dst_counts = group.groupby("dst_ip")["total_pkts"].sum().to_numpy(dtype=np.float64)
        dport_counts = group.groupby("dst_port")["total_pkts"].sum().to_numpy(dtype=np.float64)
        src_entropy = _entropy_from_counts(src_counts)
        dst_entropy = _entropy_from_counts(dst_counts)
        dport_entropy = _entropy_from_counts(dport_counts)

        pktlen_mean, pktlen_var = _agg_packet_len(group)

        tcp_cnt = float(group["tcp_cnt"].sum())
        tcp_syn = float(group["tcp_syn"].sum())
        tcp_ack = float(group["tcp_ack"].sum())
        tcp_rst = float(group["tcp_rst"].sum())
        tcp_fin = float(group["tcp_fin"].sum())
        tcp_psh = float(group["tcp_psh"].sum())
        tcp_urg = float(group["tcp_urg"].sum())
        syn_only = float(group["syn_only"].sum())
        ack_only = float(group["ack_only"].sum())
        syn_ack = float(group["syn_ack"].sum())
        rst_any = float(group["rst_any"].sum())

        syn_ratio = (tcp_syn / tcp_cnt) if tcp_cnt else 0.0
        ack_ratio = (tcp_ack / tcp_cnt) if tcp_cnt else 0.0
        rst_ratio = (tcp_rst / tcp_cnt) if tcp_cnt else 0.0
        syn_only_ratio = (syn_only / tcp_cnt) if tcp_cnt else 0.0

        proto_6 = float(group["proto_6"].sum())
        proto_17 = float(group["proto_17"].sum())
        proto_1 = float(group["proto_1"].sum())

        # label/attack_type for window
        has_attack = bool(group["is_attack"].any())
        if has_attack:
            atk_group = group[group["is_attack"] == 1]
            attack_type = str(atk_group["raw_label"].mode().iloc[0]) if not atk_group.empty else "ATTACK"
            label = 1
        else:
            attack_type = "BENIGN"
            label = 0

        features = {
            "pps": round(pps, 6),
            "bps": round(bps, 6),
            "pkt_cnt": int(pkt_cnt),
            "byte_cnt": int(byte_cnt),
            "uniq_src": uniq_src,
            "uniq_dst": uniq_dst,
            "uniq_pair": uniq_pair,
            "uniq_flow5": uniq_flow5,
            "avg_pkts_per_src": round(avg_pkts_per_src, 6),
            "avg_pkts_per_dst": round(avg_pkts_per_dst, 6),
            "src_ip_entropy": round(src_entropy, 6),
            "dst_ip_entropy": round(dst_entropy, 6),
            "dport_entropy": round(dport_entropy, 6),
            "pktlen_mean": round(pktlen_mean, 6),
            "pktlen_var": round(pktlen_var, 6),
            "tcp_cnt": int(tcp_cnt),
            "tcp_syn": int(tcp_syn),
            "tcp_ack": int(tcp_ack),
            "tcp_rst": int(tcp_rst),
            "tcp_fin": int(tcp_fin),
            "tcp_psh": int(tcp_psh),
            "tcp_urg": int(tcp_urg),
            "syn_ratio": round(syn_ratio, 6),
            "ack_ratio": round(ack_ratio, 6),
            "rst_ratio": round(rst_ratio, 6),
            "syn_only_ratio": round(syn_only_ratio, 6),
            "syn_only": int(syn_only),
            "ack_only": int(ack_only),
            "syn_ack": int(syn_ack),
            "rst_any": int(rst_any),
            "proto_cnt": {"6": int(proto_6), "17": int(proto_17), "1": int(proto_1)},
        }

        windows.append(features)
        labels.append(label)
        attack_types.append(attack_type)

    return windows, labels, attack_types


def process_file(path: Path, window_sec: float, min_flows: int, label_col: str, ts_cols: List[str], sample: int):
    df = pd.read_parquet(path)
    if sample > 0 and len(df) > sample:
        df = df.sample(n=sample, random_state=42)

    df = df.copy()

    ts_sec = _parse_timestamp(df, ts_cols)
    df["ts_sec"] = ts_sec

    df["raw_label"] = df[label_col] if label_col in df.columns else "unknown"
    df["label"] = df["raw_label"].map(_normalize_label)
    df["is_attack"] = (df["label"] != "benign").astype(int)

    proto = _safe_col(df, ["Protocol", "protocol"], 0).astype(int)
    src_ip = _safe_col(df, ["Source IP", "Src IP", "src_ip"], "0.0.0.0").astype(str)
    dst_ip = _safe_col(df, ["Destination IP", "Dst IP", "dst_ip"], "0.0.0.0").astype(str)
    src_port = _safe_col(df, ["Source Port", "Src Port", "src_port"], 0).astype(int)
    dst_port = _safe_col(df, ["Destination Port", "Dst Port", "dst_port"], 0).astype(int)

    fwd_pkts = _safe_col(df, ["Total Fwd Packets", "Tot Fwd Pkts"], 0).astype(float)
    bwd_pkts = _safe_col(df, ["Total Backward Packets", "Tot Bwd Pkts"], 0).astype(float)
    total_pkts = (fwd_pkts + bwd_pkts).clip(lower=0)

    fwd_bytes = _safe_col(
        df,
        [
            "Fwd Packets Length Total",
            "Total Length of Fwd Packets",
            "TotLen Fwd Pkts",
        ],
        0,
    ).astype(float)
    bwd_bytes = _safe_col(
        df,
        [
            "Bwd Packets Length Total",
            "Total Length of Bwd Packets",
            "TotLen Bwd Pkts",
        ],
        0,
    ).astype(float)
    total_bytes = (fwd_bytes + bwd_bytes).clip(lower=0)

    flow_dur_us = _safe_col(df, ["Flow Duration"], 0).astype(float)
    duration_sec = (flow_dur_us / 1e6).clip(lower=1e-6)

    flow_pps = _safe_col(df, ["Flow Packets/s"], 0).astype(float)
    flow_bps = _safe_col(df, ["Flow Bytes/s"], 0).astype(float)

    pps = flow_pps.where(flow_pps > 0, total_pkts / duration_sec)
    bps = flow_bps.where(flow_bps > 0, total_bytes / duration_sec)

    pktlen_mean = _safe_col(df, ["Packet Length Mean"], 0).astype(float)
    pktlen_var = _safe_col(df, ["Packet Length Variance"], 0).astype(float)
    if "Packet Length Std" in df.columns and pktlen_var.eq(0).all():
        pktlen_var = _safe_col(df, ["Packet Length Std"], 0).astype(float) ** 2
    if pktlen_mean.eq(0).all():
        pktlen_mean = (total_bytes / total_pkts.replace(0, np.nan)).fillna(0)

    syn = _safe_col(df, ["SYN Flag Count"], 0).astype(float)
    ack = _safe_col(df, ["ACK Flag Count"], 0).astype(float)
    rst = _safe_col(df, ["RST Flag Count"], 0).astype(float)
    fin = _safe_col(df, ["FIN Flag Count"], 0).astype(float)
    psh = _safe_col(df, ["PSH Flag Count"], 0).astype(float)
    urg = _safe_col(df, ["URG Flag Count"], 0).astype(float)

    syn_only = (syn - ack).clip(lower=0)
    ack_only = (ack - syn).clip(lower=0)
    syn_ack = np.minimum(syn, ack)
    rst_any = rst

    df["proto"] = proto
    df["src_ip"] = src_ip
    df["dst_ip"] = dst_ip
    df["src_port"] = src_port
    df["dst_port"] = dst_port
    df["total_pkts"] = total_pkts
    df["total_bytes"] = total_bytes
    df["pps"] = pps
    df["bps"] = bps
    df["pktlen_mean"] = pktlen_mean
    df["pktlen_var"] = pktlen_var
    df["tcp_cnt"] = total_pkts.where(proto == 6, 0.0)
    df["tcp_syn"] = syn
    df["tcp_ack"] = ack
    df["tcp_rst"] = rst
    df["tcp_fin"] = fin
    df["tcp_psh"] = psh
    df["tcp_urg"] = urg
    df["syn_only"] = syn_only
    df["ack_only"] = ack_only
    df["syn_ack"] = syn_ack
    df["rst_any"] = rst_any
    df["proto_6"] = total_pkts.where(proto == 6, 0.0)
    df["proto_17"] = total_pkts.where(proto == 17, 0.0)
    df["proto_1"] = total_pkts.where(proto == 1, 0.0)

    df["pair_key"] = df["src_ip"].astype(str) + "|" + df["dst_ip"].astype(str)
    df["flow5_key"] = (
        df["src_ip"].astype(str)
        + "|"
        + df["dst_ip"].astype(str)
        + "|"
        + df["src_port"].astype(str)
        + "|"
        + df["dst_port"].astype(str)
        + "|"
        + df["proto"].astype(str)
    )

    windows, labels, attack_types = build_windows(df, window_sec, min_flows)
    return windows, labels, attack_types


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="dl/config.yaml")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    ds_cfg = cfg.get("dataset", {})
    input_glob = ds_cfg.get("input_glob", "datasets/CICDDoS2019/*.parquet")
    output_dir = Path(ds_cfg.get("output_dir", "dl/data"))
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    window_sec = float(ds_cfg.get("window_sec", 1.0))
    sample = int(ds_cfg.get("sample_per_file", 0))
    min_flows = int(ds_cfg.get("min_flows_per_window", 1))
    label_col = str(ds_cfg.get("label_col", "Label"))
    ts_cols = ds_cfg.get("timestamp_cols", ["Timestamp"]) or ["Timestamp"]

    pattern = input_glob
    if not Path(pattern).is_absolute():
        pattern = str(ROOT / pattern)
    files = [Path(p) for p in sorted(glob.glob(pattern))]
    if not files:
        raise SystemExit(f"no parquet files matched: {input_glob}")

    output_dir.mkdir(parents=True, exist_ok=True)
    X_list = []
    y_list = []
    meta_files = []
    idx = 0

    for p in files:
        windows, labels, attack_types = process_file(
            p, window_sec, min_flows, label_col, ts_cols, sample
        )
        if not windows:
            continue
        windows = enrich_temporal_features(windows)
        start = idx
        for feat in windows:
            X_list.append(vectorize(feat))
        y_list.extend(labels)
        idx = len(X_list)
        meta_files.append(
            {
                "path": str(p),
                "start": start,
                "end": idx,
                "windows": len(windows),
                "attack_windows": int(sum(labels)),
                "attack_types": Counter([a for a in attack_types if a and a != "BENIGN"]),
            }
        )

    if not X_list:
        raise SystemExit("empty dataset after processing")

    X = np.asarray(X_list, dtype=np.float32)
    y = np.asarray(y_list, dtype=np.int64)

    np.save(output_dir / "X.npy", X)
    np.save(output_dir / "y.npy", y)

    meta = {
        "feature_order": FEATURE_ORDER,
        "window_sec": window_sec,
        "input_glob": input_glob,
        "files": [],
        "total_windows": int(X.shape[0]),
        "attack_windows": int(y.sum()),
    }

    for item in meta_files:
        item["attack_types"] = {k: int(v) for k, v in item["attack_types"].items()}
        meta["files"].append(item)

    with open(output_dir / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"[ok] X.npy shape={X.shape} y.npy shape={y.shape}")
    print(f"[ok] meta.json -> {output_dir / 'meta.json'}")


if __name__ == "__main__":
    main()
