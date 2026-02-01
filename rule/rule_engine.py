#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, json, time, argparse
from pathlib import Path

def load_rules(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def classify(features: dict, rules: dict) -> tuple[str, str, int, float, list[str]]:
    """
    返回: (label, attack_type, score, confidence, reasons)
    这里先做规则分数；attack_type 用最常见 DDoS 类型做一个“可扩展模板”
    """
    th = rules.get("thresholds", {})
    w  = rules.get("weights", {})
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

    # 命中规则加分（保持与你 rules.json 一致）
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

    # 置信度：先做个简单归一化，后续你接深度学习再替换
    max_possible = sum(int(v) for v in w.values()) if w else 1
    confidence = min(1.0, score / max_possible)

    # attack_type：先做最常见模板（你后续可以继续扩展更细）
    proto_cnt = features.get("proto_cnt", {}) or {}
    tcp_cnt = int(features.get("tcp_cnt", 0) or 0)
    udp_cnt = int(proto_cnt.get("17", proto_cnt.get(17, 0)) or 0)
    icmp_cnt = int(proto_cnt.get("1", proto_cnt.get(1, 0)) or 0)

    attack_type = "BENIGN"
    if label == "attack":
        # SYN Flood：syn_ratio 和 syn_only_ratio 高
        if syn_ratio > 0.5 and syn_only_ratio > 0.3 and tcp_cnt > 0:
            attack_type = "TCP_SYN_FLOOD"
        # UDP Flood：UDP 占比高且 pps 高
        elif udp_cnt > 0 and udp_cnt >= tcp_cnt and pps > safe_float(th.get("pps_high", 0)):
            attack_type = "UDP_FLOOD"
        # ICMP Flood：ICMP 占比高且 pps 高（如果你后续支持 ICMP 解析）
        elif icmp_cnt > 0 and pps > safe_float(th.get("pps_high", 0)):
            attack_type = "ICMP_FLOOD"
        else:
            attack_type = "SUSPECT"
    elif label == "suspect":
        attack_type = "SUSPECT"

    return label, attack_type, score, confidence, reasons

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
    args = ap.parse_args()

    rules = load_rules(args.rules_json)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            features = json.loads(line)
        except Exception:
            continue

        label, attack_type, score, confidence, reasons = classify(features, rules)
        out = {
            "ts": time.time(),
            "label": label,
            "attack_type": attack_type,
            "score": score,
            "confidence": confidence,
            "reasons": reasons,
            "features": features
        }

        # stdout 给你看实时结果
        print(json.dumps(out, ensure_ascii=False), flush=True)

        # 落盘
        if args.jsonl:
            write_jsonl(args.jsonl, out)
        if args.alerts and label != "benign":
            write_jsonl(args.alerts, out)

if __name__ == "__main__":
    main()
