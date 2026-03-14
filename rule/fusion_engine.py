#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.integration.dl_client import DLClient
from dl.integration.fusion import FusionEngine, FusionSettings


def load_rules(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def ratio(num: float, den: float) -> float:
    d = den if den > 1e-9 else 1e-9
    return num / d


def _top_dport_map(features: dict) -> dict:
    out = {}
    items = features.get("top_dport", []) or []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        try:
            port = int(item[0])
            cnt = float(item[1] or 0)
        except Exception:
            continue
        out[port] = out.get(port, 0.0) + cnt
    return out


def _typed_attack_match(features: dict, rules: dict):
    type_rules = rules.get("type_rules", {}) or {}

    pps = safe_float(features.get("pps"))
    uniq_src = int(features.get("uniq_src", 0) or 0)
    uniq_flow5 = int(features.get("uniq_flow5", 0) or 0)
    syn_ratio = safe_float(features.get("syn_ratio"))
    syn_only_ratio = safe_float(features.get("syn_only_ratio"))

    proto_cnt = features.get("proto_cnt", {}) or {}
    tcp_cnt = float(features.get("tcp_cnt", 0) or 0)
    udp_cnt = float(proto_cnt.get("17", proto_cnt.get(17, 0)) or 0)
    icmp_cnt = float(proto_cnt.get("1", proto_cnt.get(1, 0)) or 0)
    pkt_cnt = float(features.get("pkt_cnt", 0) or 0)
    total_pkts = max(pkt_cnt, tcp_cnt + udp_cnt + icmp_cnt, 1.0)
    udp_ratio = ratio(udp_cnt, total_pkts)
    icmp_ratio = ratio(icmp_cnt, total_pkts)
    ack_ratio = safe_float(features.get("ack_ratio"))
    rst_ratio = safe_float(features.get("rst_ratio"))
    ack_only = safe_float(features.get("ack_only"))
    syn_ack = safe_float(features.get("syn_ack"))
    tcp_psh = safe_float(features.get("tcp_psh"))
    pktlen_mean = safe_float(features.get("pktlen_mean"))
    ack_only_ratio = ratio(ack_only, max(tcp_cnt, 1.0))
    syn_ack_ratio = ratio(syn_ack, max(tcp_cnt, 1.0))
    psh_ratio = ratio(tcp_psh, max(tcp_cnt, 1.0))
    top_dport = _top_dport_map(features)
    ssh_ratio = ratio(top_dport.get(22, 0.0), max(tcp_cnt, 1.0))

    syn_cfg = type_rules.get("tcp_syn_flood", {}) or {}
    syn_enabled = bool(syn_cfg.get("enabled", True))
    syn_min_pps = safe_float(syn_cfg.get("min_pps", 120))
    syn_min_tcp = safe_float(syn_cfg.get("min_tcp_cnt", 80))
    syn_min_syn_ratio = safe_float(syn_cfg.get("min_syn_ratio", 0.55))
    syn_min_syn_only_ratio = safe_float(syn_cfg.get("min_syn_only_ratio", 0.25))
    syn_cnt = safe_float(features.get("tcp_syn"))
    syn_min_syn_pkts = safe_float(syn_cfg.get("min_syn_pkts", max(60.0, syn_min_tcp * 0.8)))
    syn_relaxed_ratio = safe_float(syn_cfg.get("relaxed_syn_ratio", max(0.25, syn_min_syn_ratio * 0.5)))
    syn_relaxed_syn_only_ratio = safe_float(
        syn_cfg.get("relaxed_syn_only_ratio", max(0.1, syn_min_syn_only_ratio * 0.5))
    )
    syn_strict_hit = (
        pps >= syn_min_pps
        and tcp_cnt >= syn_min_tcp
        and syn_ratio >= syn_min_syn_ratio
        and syn_only_ratio >= syn_min_syn_only_ratio
    )
    syn_relaxed_hit = (
        pps >= syn_min_pps
        and tcp_cnt >= syn_min_tcp
        and syn_cnt >= syn_min_syn_pkts
        and syn_ratio >= syn_relaxed_ratio
        and syn_only_ratio >= syn_relaxed_syn_only_ratio
    )
    syn_hit = syn_enabled and (syn_strict_hit or syn_relaxed_hit)
    syn_conf = clamp(
        0.20
        + 0.30 * clamp(ratio(pps, syn_min_pps))
        + 0.25 * clamp(ratio(tcp_cnt, syn_min_tcp))
        + 0.15 * clamp(ratio(syn_ratio, syn_min_syn_ratio))
        + 0.10 * clamp(ratio(syn_only_ratio, syn_min_syn_only_ratio))
    )

    udp_cfg = type_rules.get("udp_flood", {}) or {}
    udp_enabled = bool(udp_cfg.get("enabled", True))
    udp_min_pps = safe_float(udp_cfg.get("min_pps", 150))
    udp_min_udp = safe_float(udp_cfg.get("min_udp_cnt", 90))
    udp_min_ratio = safe_float(udp_cfg.get("min_udp_ratio", 0.65))
    udp_min_flow5 = int(udp_cfg.get("min_uniq_flow5", 20) or 20)
    udp_hit = udp_enabled and (
        pps >= udp_min_pps
        and udp_cnt >= udp_min_udp
        and udp_ratio >= udp_min_ratio
        and uniq_flow5 >= udp_min_flow5
    )
    udp_conf = clamp(
        0.22
        + 0.28 * clamp(ratio(pps, udp_min_pps))
        + 0.20 * clamp(ratio(udp_cnt, udp_min_udp))
        + 0.20 * clamp(ratio(udp_ratio, udp_min_ratio))
        + 0.10 * clamp(ratio(uniq_flow5, max(udp_min_flow5, 1)))
    )

    icmp_cfg = type_rules.get("icmp_flood", {}) or {}
    icmp_enabled = bool(icmp_cfg.get("enabled", True))
    icmp_min_pps = safe_float(icmp_cfg.get("min_pps", 120))
    icmp_min_icmp = safe_float(icmp_cfg.get("min_icmp_cnt", 60))
    icmp_min_ratio = safe_float(icmp_cfg.get("min_icmp_ratio", 0.60))
    icmp_hit = icmp_enabled and pps >= icmp_min_pps and icmp_cnt >= icmp_min_icmp and icmp_ratio >= icmp_min_ratio
    icmp_conf = clamp(
        0.24
        + 0.34 * clamp(ratio(pps, icmp_min_pps))
        + 0.20 * clamp(ratio(icmp_cnt, icmp_min_icmp))
        + 0.22 * clamp(ratio(icmp_ratio, icmp_min_ratio))
    )

    ack_cfg = type_rules.get("tcp_ack_flood", {}) or {}
    ack_enabled = bool(ack_cfg.get("enabled", False))
    if ack_enabled:
        ack_min_pps = safe_float(ack_cfg.get("min_pps", 350))
        ack_single_src_min_pps = safe_float(ack_cfg.get("single_src_min_pps", max(ack_min_pps * 3.0, 1000.0)))
        ack_min_tcp = safe_float(ack_cfg.get("min_tcp_cnt", 250))
        ack_min_ratio = safe_float(ack_cfg.get("min_ack_ratio", 0.9))
        ack_min_ack_only_ratio = safe_float(ack_cfg.get("min_ack_only_ratio", 0.55))
        ack_max_syn = safe_float(ack_cfg.get("max_syn_ratio", 0.08))
        ack_max_syn_ack_ratio = safe_float(ack_cfg.get("max_syn_ack_ratio", 0.06))
        ack_max_psh_ratio = safe_float(ack_cfg.get("max_psh_ratio", 0.12))
        ack_max_pktlen_mean = safe_float(ack_cfg.get("max_pktlen_mean", 120.0))
        ack_min_uniq_src = int(ack_cfg.get("min_uniq_src", 3) or 3)
        ack_min_uniq_flow5 = int(ack_cfg.get("min_uniq_flow5", 12) or 12)
        ack_allow_ssh = bool(ack_cfg.get("allow_ssh_dominant", False))
        ack_max_ssh_ratio = safe_float(ack_cfg.get("max_ssh_dport_ratio", 0.2))
        ack_port_ok = ack_allow_ssh or ssh_ratio <= ack_max_ssh_ratio
        ack_src_ok = uniq_src >= ack_min_uniq_src or (uniq_src <= 1 and pps >= ack_single_src_min_pps)
        ack_pktlen_ok = ack_max_pktlen_mean <= 0 or pktlen_mean <= ack_max_pktlen_mean
        ack_hit = (
            pps >= ack_min_pps
            and tcp_cnt >= ack_min_tcp
            and ack_ratio >= ack_min_ratio
            and ack_only_ratio >= ack_min_ack_only_ratio
            and syn_ratio <= ack_max_syn
            and syn_ack_ratio <= ack_max_syn_ack_ratio
            and psh_ratio <= ack_max_psh_ratio
            and ack_src_ok
            and uniq_flow5 >= ack_min_uniq_flow5
            and ack_port_ok
            and ack_pktlen_ok
        )
        ack_conf = clamp(
            0.22
            + 0.30 * clamp(ratio(pps, ack_min_pps))
            + 0.20 * clamp(ratio(tcp_cnt, ack_min_tcp))
            + 0.20 * clamp(ratio(ack_ratio, ack_min_ratio))
            + 0.04 * clamp(ratio(ack_only_ratio, max(ack_min_ack_only_ratio, 1e-9)))
            + 0.04 * clamp(ratio(max(ack_max_syn - syn_ratio, 0.0), max(ack_max_syn, 1e-9)))
        )
    else:
        ack_hit = False
        ack_conf = 0.0

    rst_cfg = type_rules.get("tcp_rst_flood", {}) or {}
    rst_enabled = bool(rst_cfg.get("enabled", False))
    if rst_enabled:
        rst_min_pps = safe_float(rst_cfg.get("min_pps", 350))
        rst_single_src_min_pps = safe_float(rst_cfg.get("single_src_min_pps", max(rst_min_pps * 3.0, 1000.0)))
        rst_min_tcp = safe_float(rst_cfg.get("min_tcp_cnt", 250))
        rst_min_ratio = safe_float(rst_cfg.get("min_rst_ratio", 0.5))
        rst_max_syn_ratio = safe_float(rst_cfg.get("max_syn_ratio", 0.2))
        rst_max_syn_ack_ratio = safe_float(rst_cfg.get("max_syn_ack_ratio", 0.08))
        rst_max_psh_ratio = safe_float(rst_cfg.get("max_psh_ratio", 0.12))
        rst_max_pktlen_mean = safe_float(rst_cfg.get("max_pktlen_mean", 120.0))
        rst_min_uniq_src = int(rst_cfg.get("min_uniq_src", 3) or 3)
        rst_min_uniq_flow5 = int(rst_cfg.get("min_uniq_flow5", 12) or 12)
        rst_allow_ssh = bool(rst_cfg.get("allow_ssh_dominant", False))
        rst_max_ssh_ratio = safe_float(rst_cfg.get("max_ssh_dport_ratio", 0.2))
        rst_port_ok = rst_allow_ssh or ssh_ratio <= rst_max_ssh_ratio
        rst_src_ok = uniq_src >= rst_min_uniq_src or (uniq_src <= 1 and pps >= rst_single_src_min_pps)
        rst_pktlen_ok = rst_max_pktlen_mean <= 0 or pktlen_mean <= rst_max_pktlen_mean
        rst_hit = (
            pps >= rst_min_pps
            and tcp_cnt >= rst_min_tcp
            and rst_ratio >= rst_min_ratio
            and syn_ratio <= rst_max_syn_ratio
            and syn_ack_ratio <= rst_max_syn_ack_ratio
            and psh_ratio <= rst_max_psh_ratio
            and rst_src_ok
            and uniq_flow5 >= rst_min_uniq_flow5
            and rst_port_ok
            and rst_pktlen_ok
        )
        rst_conf = clamp(
            0.22
            + 0.30 * clamp(ratio(pps, rst_min_pps))
            + 0.20 * clamp(ratio(tcp_cnt, rst_min_tcp))
            + 0.24 * clamp(ratio(rst_ratio, rst_min_ratio))
            + 0.02 * clamp(ratio(max(rst_max_syn_ratio - syn_ratio, 0.0), max(rst_max_syn_ratio, 1e-9)))
            + 0.02 * clamp(ratio(max(rst_max_syn_ack_ratio - syn_ack_ratio, 0.0), max(rst_max_syn_ack_ratio, 1e-9)))
        )
    else:
        rst_hit = False
        rst_conf = 0.0

    def _udp_amp_hit(name: str, port: int, default_pps: float, default_udp_cnt: float, default_udp_ratio: float):
        cfg = type_rules.get(name, {}) or {}
        if not bool(cfg.get("enabled", False)):
            return False, 0.0, 0.0
        min_pps = safe_float(cfg.get("min_pps", default_pps))
        min_udp_cnt = safe_float(cfg.get("min_udp_cnt", default_udp_cnt))
        min_udp_ratio = safe_float(cfg.get("min_udp_ratio", default_udp_ratio))
        min_port_hits = safe_float(cfg.get("min_port_hits", max(default_udp_cnt * 0.4, 40.0)))
        hits = float(top_dport.get(port, 0.0))
        is_hit = (
            pps >= min_pps
            and udp_cnt >= min_udp_cnt
            and udp_ratio >= min_udp_ratio
            and hits >= min_port_hits
        )
        conf = clamp(
            0.20
            + 0.22 * clamp(ratio(pps, min_pps))
            + 0.22 * clamp(ratio(udp_cnt, min_udp_cnt))
            + 0.18 * clamp(ratio(udp_ratio, min_udp_ratio))
            + 0.18 * clamp(ratio(hits, min_port_hits))
        )
        return is_hit, conf, hits

    dns_hit, dns_conf, dns_hits = _udp_amp_hit("dns_amp_flood", 53, 120, 80, 0.6)
    ntp_hit, ntp_conf, ntp_hits = _udp_amp_hit("ntp_amp_flood", 123, 120, 80, 0.6)
    ssdp_hit, ssdp_conf, ssdp_hits = _udp_amp_hit("ssdp_amp_flood", 1900, 120, 80, 0.55)
    cldap_hit, cldap_conf, cldap_hits = _udp_amp_hit("cldap_amp_flood", 389, 120, 80, 0.55)
    mem_hit, mem_conf, mem_hits = _udp_amp_hit("memcached_amp_flood", 11211, 100, 70, 0.5)
    snmp_hit, snmp_conf, snmp_hits = _udp_amp_hit("snmp_amp_flood", 161, 120, 80, 0.55)

    matched = []
    if syn_hit:
        matched.append(("TCP_SYN_FLOOD", syn_conf))
    if udp_hit:
        matched.append(("UDP_FLOOD", udp_conf))
    if icmp_hit:
        matched.append(("ICMP_FLOOD", icmp_conf))
    if ack_hit:
        matched.append(("TCP_ACK_FLOOD", ack_conf))
    if rst_hit:
        matched.append(("TCP_RST_FLOOD", rst_conf))
    if dns_hit:
        matched.append(("DNS_AMP_FLOOD", dns_conf))
    if ntp_hit:
        matched.append(("NTP_AMP_FLOOD", ntp_conf))
    if ssdp_hit:
        matched.append(("SSDP_AMP_FLOOD", ssdp_conf))
    if cldap_hit:
        matched.append(("CLDAP_AMP_FLOOD", cldap_conf))
    if mem_hit:
        matched.append(("MEMCACHED_AMP_FLOOD", mem_conf))
    if snmp_hit:
        matched.append(("SNMP_AMP_FLOOD", snmp_conf))
    if not matched:
        return None, 0.0

    matched.sort(key=lambda x: x[1], reverse=True)
    return matched[0]


def classify_rule(features: dict, rules: dict):
    th = rules.get("thresholds", {})
    w = rules.get("weights", {})
    decision = rules.get("decision", {}) or {}
    suspect_score = decision.get("suspect_score", 4)
    attack_score = decision.get("attack_score", suspect_score + 2)

    score = 0
    reasons = []

    pps = safe_float(features.get("pps"))
    bps = safe_float(features.get("bps"))
    uniq_src = int(features.get("uniq_src", 0) or 0)
    uniq_flow5 = int(features.get("uniq_flow5", 0) or 0)
    syn_ratio = safe_float(features.get("syn_ratio"))
    syn_only_ratio = safe_float(features.get("syn_only_ratio"))
    cardinality_min_pps = safe_float(th.get("cardinality_min_pps", 120))

    def hit(name: str, cond: bool, detail: str):
        nonlocal score
        if cond:
            score += int(w.get(name, 1))
            reasons.append(f"{name}:{detail}")

    hit("pps_high", pps > safe_float(th.get("pps_high")), f"pps={pps}")
    hit("bps_high", bps > safe_float(th.get("bps_high")), f"bps={bps}")
    hit(
        "uniq_src_high",
        pps >= cardinality_min_pps and uniq_src > int(th.get("uniq_src_high", 0)),
        f"uniq_src={uniq_src}",
    )
    hit(
        "uniq_flow5_high",
        pps >= cardinality_min_pps and uniq_flow5 > int(th.get("uniq_flow5_high", 0)),
        f"uniq_flow5={uniq_flow5}",
    )
    hit("syn_ratio_high", syn_ratio > safe_float(th.get("syn_ratio_high")), f"syn_ratio={syn_ratio}")
    hit("syn_only_ratio_high", syn_only_ratio > safe_float(th.get("syn_only_ratio_high")), f"syn_only_ratio={syn_only_ratio}")

    if score >= attack_score:
        label = "attack"
    elif score >= suspect_score:
        label = "suspect"
    else:
        label = "benign"

    max_possible = sum(int(v) for v in w.values()) if w else 1
    confidence = min(1.0, score / max_possible)

    typed_type, typed_conf = _typed_attack_match(features, rules)

    attack_type = "BENIGN"
    if typed_type:
        # Typed-rule channel has higher priority for common known attacks.
        label = "attack"
        attack_type = typed_type
        confidence = max(confidence, typed_conf)
        score = max(score, attack_score)
        reasons.append(f"type_hit:{typed_type}")
        reasons.append(f"type_conf:{round(typed_conf, 3)}")
    elif label == "attack":
        attack_type = "ATTACK"
    elif label == "suspect":
        attack_type = "SUSPECT"

    return label, attack_type, score, confidence, reasons


def build_fusion_engine(rules: dict, args) -> FusionEngine:
    decision = rules.get("decision", {}) or {}
    dl_attack = decision.get("dl_attack_score", decision.get("ml_attack_score", 0.7))
    dl_suspect = decision.get("dl_suspect_score", decision.get("ml_suspect_score", 0.5))
    dl_type_confirm = decision.get("dl_type_confirm_min", decision.get("type_confirm_min", 0.6))
    rule_conf = decision.get("rule_confidence_min", 0.6)
    type_confirm_min = decision.get("type_confirm_min", 0.45)
    seq_len = decision.get("dl_seq_len", 10)
    known = decision.get(
        "known_rule_attacks",
        [
            "UDP_FLOOD",
            "TCP_SYN_FLOOD",
            "ICMP_FLOOD",
            "TCP_ACK_FLOOD",
            "TCP_RST_FLOOD",
            "DNS_AMP_FLOOD",
            "NTP_AMP_FLOOD",
            "SSDP_AMP_FLOOD",
            "CLDAP_AMP_FLOOD",
            "MEMCACHED_AMP_FLOOD",
            "SNMP_AMP_FLOOD",
        ],
    )

    dl_url = args.dl_url or decision.get("dl_url") or os.environ.get("DL_URL", "")
    timeout = args.dl_timeout if args.dl_timeout is not None else decision.get("dl_timeout", 0.6)

    client = DLClient(dl_url, timeout=float(timeout)) if dl_url else None
    settings = FusionSettings(
        seq_len=int(seq_len),
        dl_attack_score=float(dl_attack),
        dl_suspect_score=float(dl_suspect),
        dl_type_confirm_min=float(dl_type_confirm),
        rule_confidence_min=float(rule_conf),
        type_confirm_min=float(type_confirm_min),
        known_rule_attacks=set(known),
        gate_min_rule_score=float(decision.get("gate_min_rule_score", 0.0)),
        gate_low_pps=float(decision.get("gate_low_pps", 120.0)),
        gate_low_uniq_src=int(decision.get("gate_low_uniq_src", 3)),
        gate_low_uniq_flow5=int(decision.get("gate_low_uniq_flow5", 30)),
        gate_low_syn_ratio=float(decision.get("gate_low_syn_ratio", 0.2)),
        gate_low_syn_only_ratio=float(decision.get("gate_low_syn_only_ratio", 0.05)),
        gate_streak=int(decision.get("gate_streak", 3)),
        gate_sample_every=int(decision.get("gate_sample_every", 10)),
        gate_cooldown_windows=int(decision.get("gate_cooldown_windows", 8)),
        enable_low_risk_gate=bool(decision.get("enable_low_risk_gate", False)),
        dl_error_as_suspect=bool(decision.get("dl_error_as_suspect", True)),
        dl_warmup_pad=bool(decision.get("dl_warmup_pad", True)),
    )
    return FusionEngine(client, settings)


def known_rule_attacks(rules: dict) -> set:
    decision = rules.get("decision", {}) or {}
    known = decision.get(
        "known_rule_attacks",
        [
            "UDP_FLOOD",
            "TCP_SYN_FLOOD",
            "ICMP_FLOOD",
            "TCP_ACK_FLOOD",
            "TCP_RST_FLOOD",
            "DNS_AMP_FLOOD",
            "NTP_AMP_FLOOD",
            "SSDP_AMP_FLOOD",
            "CLDAP_AMP_FLOOD",
            "MEMCACHED_AMP_FLOOD",
            "SNMP_AMP_FLOOD",
        ],
    )
    return {str(x or "").strip().upper() for x in known if str(x or "").strip()}


def write_jsonl(path: str, obj: dict):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        f.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_json", help="rules.json path")
    ap.add_argument("--jsonl", default="", help="append all events to this jsonl file (optional)")
    ap.add_argument("--alerts", default="", help="append only suspect/attack to this jsonl file (optional)")
    ap.add_argument("--persist-benign", action="store_true", help="also persist benign rows to --jsonl")
    ap.add_argument("--emit-benign", action="store_true", help="also print benign rows to stdout")
    ap.add_argument("--fuse", action="store_true", help="enable rule-first + DL-fallback fusion")
    ap.add_argument("--dl-only", action="store_true", help="validation mode: bypass rule decision and let DL decide")
    ap.add_argument("--dl-url", default="", help="DL service URL, e.g. http://127.0.0.1:8001/predict")
    ap.add_argument("--dl-timeout", type=float, default=None, help="DL request timeout (sec)")
    args = ap.parse_args()

    rules = load_rules(args.rules_json)
    typed_attacks = known_rule_attacks(rules)

    global_fusion_engine = build_fusion_engine(rules, args) if args.fuse else None

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            features = json.loads(line)
        except Exception:
            continue

        raw_rule_out = classify_rule(features, rules)
        rule_out = raw_rule_out
        split_scope = str(features.get("split_scope", "global") or "global").strip().lower()

        # Channel windows are used only for known typed attacks. Suppress generic
        # attack/suspect outcomes here and leave ambiguous traffic to the global path.
        if split_scope == "channel":
            raw_label, raw_attack_type, _, _, raw_reasons = raw_rule_out
            raw_attack_type = str(raw_attack_type or "").strip().upper()
            keep_channel_alert = raw_label == "attack" and raw_attack_type in typed_attacks
            if not keep_channel_alert:
                channel_reasons = list(raw_reasons or [])
                if raw_label in ("attack", "suspect"):
                    channel_reasons.append("channel_generic_suppressed:true")
                    channel_reasons.append(f"channel_raw_label:{raw_label}")
                    channel_reasons.append(f"channel_raw_attack_type:{raw_attack_type or 'BENIGN'}")
                rule_out = ("benign", "BENIGN", 0, 0.0, channel_reasons)

        if args.dl_only:
            raw_reasons = list(raw_rule_out[4] or [])
            raw_reasons.append("override:dl_only")
            rule_out = ("benign", "BENIGN", 0, 0.0, raw_reasons)

        label, attack_type, score, confidence, reasons = rule_out
        rule_label, rule_attack_type, rule_score, rule_confidence, _ = raw_rule_out
        decision_source = "rules"
        final_label = label
        final_attack_type = attack_type
        dl_p_attack = None
        dl_model_version = None
        dl_error = None
        dl_type_probs = None
        dl_extra_type = None
        dl_extra_confidence = None

        run_dl_fusion = split_scope == "global"

        if global_fusion_engine is not None and run_dl_fusion:
            fusion = global_fusion_engine.update(features, rule_out)
            final_label = fusion.final_label
            final_attack_type = fusion.final_attack_type
            decision_source = fusion.decision_source
            dl_p_attack = fusion.dl_p_attack
            dl_model_version = fusion.dl_model_version
            dl_error = fusion.dl_error
            dl_type_probs = fusion.dl_type_probs
            dl_extra_type = fusion.dl_extra_type
            dl_extra_confidence = fusion.dl_extra_confidence

            reasons = list(reasons)
            reasons.append(f"decision_source:{decision_source}")
            if dl_p_attack is not None:
                reasons.append(f"dl_p_attack:{round(float(dl_p_attack), 6)}")
            if isinstance(dl_type_probs, dict) and dl_type_probs:
                top3 = sorted(dl_type_probs.items(), key=lambda x: float(x[1]), reverse=True)[:3]
                reasons.append(
                    "dl_top3:" + ",".join(f"{k}={round(float(v), 3)}" for k, v in top3)
                )
            if dl_extra_type:
                conf_txt = round(float(dl_extra_confidence or 0.0), 6)
                reasons.append(f"dl_extra_type:{dl_extra_type}")
                reasons.append(f"dl_extra_confidence:{conf_txt}")
            if dl_error:
                reasons.append(f"dl_error:{dl_error}")
        else:
            reasons = list(reasons)
            reasons.append(f"decision_source:{decision_source}")
        label = final_label
        attack_type = final_attack_type

        out = {
            "ts": time.time(),
            "label": label,
            "attack_type": attack_type,
            "score": rule_score,
            "confidence": rule_confidence,
            "reasons": reasons,
            "features": features,
            "decision_source": decision_source,
            "final_label": final_label,
            "final_attack_type": final_attack_type,
            "dl_only_mode": bool(args.dl_only),
            "dl_p_attack": dl_p_attack,
            "dl_model_version": dl_model_version,
            "dl_error": dl_error,
            "dl_type_probs": dl_type_probs,
            "dl_extra_type": dl_extra_type,
            "dl_extra_confidence": dl_extra_confidence,
            "rule_label": rule_label,
            "rule_attack_type": rule_attack_type,
        }

        is_alert = label in ("attack", "suspect")
        if is_alert or args.emit_benign:
            print(json.dumps(out, ensure_ascii=False), flush=True)

        if args.jsonl and (is_alert or args.persist_benign):
            write_jsonl(args.jsonl, out)
        if args.alerts and is_alert and args.alerts != args.jsonl:
            write_jsonl(args.alerts, out)


if __name__ == "__main__":
    main()
