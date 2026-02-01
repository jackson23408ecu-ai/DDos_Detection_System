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

    def hit(name: str, cond: bool, detail: str):
        nonlocal score
        if cond:
            score += int(w.get(name, 1))
            reasons.append(f"{name}:{detail}")

    hit("pps_high", pps > safe_float(th.get("pps_high")), f"pps={pps}")
    hit("bps_high", bps > safe_float(th.get("bps_high")), f"bps={bps}")
    hit("uniq_src_high", uniq_src > int(th.get("uniq_src_high", 0)), f"uniq_src={uniq_src}")
    hit("uniq_flow5_high", uniq_flow5 > int(th.get("uniq_flow5_high", 0)), f"uniq_flow5={uniq_flow5}")
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

    proto_cnt = features.get("proto_cnt", {}) or {}
    tcp_cnt = int(features.get("tcp_cnt", 0) or 0)
    udp_cnt = int(proto_cnt.get("17", proto_cnt.get(17, 0)) or 0)
    icmp_cnt = int(proto_cnt.get("1", proto_cnt.get(1, 0)) or 0)

    attack_type = "BENIGN"
    if label == "attack":
        if syn_ratio > 0.5 and syn_only_ratio > 0.3 and tcp_cnt > 0:
            attack_type = "TCP_SYN_FLOOD"
        elif udp_cnt > 0 and udp_cnt >= tcp_cnt and pps > safe_float(th.get("pps_high", 0)):
            attack_type = "UDP_FLOOD"
        elif icmp_cnt > 0 and pps > safe_float(th.get("pps_high", 0)):
            attack_type = "ICMP_FLOOD"
        else:
            attack_type = "ATTACK"
    elif label == "suspect":
        attack_type = "SUSPECT"

    return label, attack_type, score, confidence, reasons


def build_fusion_engine(rules: dict, args) -> FusionEngine:
    decision = rules.get("decision", {}) or {}
    dl_attack = decision.get("dl_attack_score", decision.get("ml_attack_score", 0.7))
    dl_suspect = decision.get("dl_suspect_score", decision.get("ml_suspect_score", 0.5))
    rule_conf = decision.get("rule_confidence_min", 0.6)
    seq_len = decision.get("dl_seq_len", 10)
    known = decision.get("known_rule_attacks", ["UDP_FLOOD", "TCP_SYN_FLOOD", "ICMP_FLOOD"])

    dl_url = args.dl_url or decision.get("dl_url") or os.environ.get("DL_URL", "")
    timeout = args.dl_timeout if args.dl_timeout is not None else decision.get("dl_timeout", 0.6)

    client = DLClient(dl_url, timeout=float(timeout)) if dl_url else None
    settings = FusionSettings(
        seq_len=int(seq_len),
        dl_attack_score=float(dl_attack),
        dl_suspect_score=float(dl_suspect),
        rule_confidence_min=float(rule_conf),
        known_rule_attacks=set(known),
    )
    return FusionEngine(client, settings)


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
    ap.add_argument("--fuse", action="store_true", help="enable rule-first + DL-fallback fusion")
    ap.add_argument("--dl-url", default="", help="DL service URL, e.g. http://127.0.0.1:8001/predict")
    ap.add_argument("--dl-timeout", type=float, default=None, help="DL request timeout (sec)")
    args = ap.parse_args()

    rules = load_rules(args.rules_json)

    fusion_engine = build_fusion_engine(rules, args) if args.fuse else None

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            features = json.loads(line)
        except Exception:
            continue

        rule_out = classify_rule(features, rules)

        label, attack_type, score, confidence, reasons = rule_out
        decision_source = "rules"
        final_label = label
        final_attack_type = attack_type
        dl_p_attack = None
        dl_model_version = None
        dl_error = None

        if fusion_engine is not None:
            fusion = fusion_engine.update(features, rule_out)
            final_label = fusion.final_label
            final_attack_type = fusion.final_attack_type
            decision_source = fusion.decision_source
            dl_p_attack = fusion.dl_p_attack
            dl_model_version = fusion.dl_model_version
            dl_error = fusion.dl_error

            reasons = list(reasons)
            reasons.append(f"decision_source:{decision_source}")
            if dl_p_attack is not None:
                reasons.append(f"dl_p_attack:{round(float(dl_p_attack), 6)}")
            if dl_error:
                reasons.append(f"dl_error:{dl_error}")
        label = final_label
        attack_type = final_attack_type

        out = {
            "ts": time.time(),
            "label": label,
            "attack_type": attack_type,
            "score": score,
            "confidence": confidence,
            "reasons": reasons,
            "features": features,
            "decision_source": decision_source,
            "final_label": final_label,
            "final_attack_type": final_attack_type,
            "dl_p_attack": dl_p_attack,
            "dl_model_version": dl_model_version,
            "dl_error": dl_error,
            "rule_label": rule_out[0],
            "rule_attack_type": rule_out[1],
        }

        print(json.dumps(out, ensure_ascii=False), flush=True)

        if args.jsonl:
            write_jsonl(args.jsonl, out)
        if args.alerts and label != "benign":
            write_jsonl(args.alerts, out)


if __name__ == "__main__":
    main()
