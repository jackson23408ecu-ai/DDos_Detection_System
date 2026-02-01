#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Feature specification shared by dataset, training, and inference."""

import math
from typing import Dict, List

FEATURE_ORDER: List[str] = [
    "pps",
    "bps",
    "pkt_cnt",
    "byte_cnt",
    "uniq_src",
    "uniq_dst",
    "uniq_pair",
    "uniq_flow5",
    "avg_pkts_per_src",
    "avg_pkts_per_dst",
    "src_ip_entropy",
    "dst_ip_entropy",
    "dport_entropy",
    "pktlen_mean",
    "pktlen_var",
    "tcp_cnt",
    "tcp_syn",
    "tcp_ack",
    "tcp_rst",
    "tcp_fin",
    "tcp_psh",
    "tcp_urg",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "syn_only_ratio",
    "syn_only",
    "ack_only",
    "syn_ack",
    "rst_any",
    "proto_6",
    "proto_17",
    "proto_1",
]


def _safe_float(x, default: float = 0.0) -> float:
    try:
        if x is None:
            return default
        if isinstance(x, bool):
            return float(int(x))
        return float(x)
    except Exception:
        return default


def flatten_features(features: Dict) -> Dict[str, float]:
    proto_cnt = features.get("proto_cnt", {}) or {}
    flat = {
        "proto_6": _safe_float(proto_cnt.get("6", proto_cnt.get(6, 0))),
        "proto_17": _safe_float(proto_cnt.get("17", proto_cnt.get(17, 0))),
        "proto_1": _safe_float(proto_cnt.get("1", proto_cnt.get(1, 0))),
    }
    for k, v in features.items():
        if k in ("proto_cnt",):
            continue
        flat[k] = _safe_float(v)
    return flat


def vectorize(features: Dict) -> List[float]:
    flat = flatten_features(features)
    return [_safe_float(flat.get(k, 0.0)) for k in FEATURE_ORDER]


def standardize(vec: List[float], mean: List[float], std: List[float]) -> List[float]:
    out = []
    for i, v in enumerate(vec):
        mu = mean[i] if i < len(mean) else 0.0
        sd = std[i] if i < len(std) else 1.0
        if sd <= 1e-12:
            out.append(v - mu)
        else:
            out.append((v - mu) / sd)
    return out


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)
