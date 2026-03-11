#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Feature specification shared by dataset, training, and inference."""

import math
from typing import Dict, List, Sequence

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
    # Temporal/rolling features (for slow-rate and pulse attacks)
    "pps_ma5",
    "pps_ma10",
    "pps_cv5",
    "pkt_ma5",
    "uniq_src_ma5",
    "syn_ratio_ma5",
    "ack_ratio_ma5",
    "burst_ratio5",
    "slope_pps5",
    "pkt_delta1",
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


def vectorize_with_order(features: Dict, order: Sequence[str]) -> List[float]:
    flat = flatten_features(features)
    return [_safe_float(flat.get(k, 0.0)) for k in order]


def vectorize(features: Dict) -> List[float]:
    return vectorize_with_order(features, FEATURE_ORDER)


def _mean(vals: List[float]) -> float:
    if not vals:
        return 0.0
    return float(sum(vals) / len(vals))


def _std(vals: List[float], mu: float) -> float:
    if not vals:
        return 0.0
    return float(math.sqrt(sum((v - mu) ** 2 for v in vals) / len(vals)))


def enrich_temporal_features(seq: Sequence[Dict]) -> List[Dict]:
    """
    Add rolling features for each window in the sequence.
    Keep pure function behavior: return copied dict items.
    """
    out: List[Dict] = []
    pps_hist: List[float] = []
    pkt_hist: List[float] = []
    uniq_src_hist: List[float] = []
    syn_ratio_hist: List[float] = []
    ack_ratio_hist: List[float] = []

    prev_pkt = 0.0
    for i, raw in enumerate(seq):
        cur = dict(raw or {})
        pps = _safe_float(cur.get("pps"))
        pkt = _safe_float(cur.get("pkt_cnt"))
        uniq_src = _safe_float(cur.get("uniq_src"))
        syn_ratio = _safe_float(cur.get("syn_ratio"))
        ack_ratio = _safe_float(cur.get("ack_ratio"))

        pps_hist.append(pps)
        pkt_hist.append(pkt)
        uniq_src_hist.append(uniq_src)
        syn_ratio_hist.append(syn_ratio)
        ack_ratio_hist.append(ack_ratio)

        last5_pps = pps_hist[-5:]
        last10_pps = pps_hist[-10:]
        last5_pkt = pkt_hist[-5:]
        last5_uniq_src = uniq_src_hist[-5:]
        last5_syn = syn_ratio_hist[-5:]
        last5_ack = ack_ratio_hist[-5:]

        pps_ma5 = _mean(last5_pps)
        pps_ma10 = _mean(last10_pps)
        pps_std5 = _std(last5_pps, pps_ma5)
        pps_cv5 = (pps_std5 / pps_ma5) if pps_ma5 > 1e-9 else 0.0

        pkt_ma5 = _mean(last5_pkt)
        uniq_src_ma5 = _mean(last5_uniq_src)
        syn_ratio_ma5 = _mean(last5_syn)
        ack_ratio_ma5 = _mean(last5_ack)

        burst_ratio5 = (pps / pps_ma5) if pps_ma5 > 1e-9 else 0.0
        slope_pps5 = pps - last5_pps[0]
        pkt_delta1 = pkt - (prev_pkt if i > 0 else pkt)

        cur["pps_ma5"] = round(pps_ma5, 6)
        cur["pps_ma10"] = round(pps_ma10, 6)
        cur["pps_cv5"] = round(pps_cv5, 6)
        cur["pkt_ma5"] = round(pkt_ma5, 6)
        cur["uniq_src_ma5"] = round(uniq_src_ma5, 6)
        cur["syn_ratio_ma5"] = round(syn_ratio_ma5, 6)
        cur["ack_ratio_ma5"] = round(ack_ratio_ma5, 6)
        cur["burst_ratio5"] = round(burst_ratio5, 6)
        cur["slope_pps5"] = round(slope_pps5, 6)
        cur["pkt_delta1"] = round(pkt_delta1, 6)

        prev_pkt = pkt
        out.append(cur)
    return out


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
