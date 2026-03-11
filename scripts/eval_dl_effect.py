#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from collections import Counter
from pathlib import Path


def load_rows(path: Path):
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def summarize(rows):
    c = Counter()
    dl_override = 0
    dl_attack_like = 0
    p_attack_hist = {"<0.5": 0, "0.5-0.65": 0, "0.65-0.82": 0, ">=0.82": 0}
    for x in rows:
        src = str(x.get("decision_source", "rules"))
        lbl = str(x.get("final_label", x.get("label", "")))
        c[f"decision_{src}"] += 1
        c[f"final_{lbl}"] += 1

        rl = str(x.get("rule_label", ""))
        if rl == "benign" and lbl in ("suspect", "attack"):
            dl_override += 1

        p = x.get("dl_p_attack")
        if p is None:
            continue
        try:
            p = float(p)
        except Exception:
            continue
        if p < 0.5:
            p_attack_hist["<0.5"] += 1
        elif p < 0.65:
            p_attack_hist["0.5-0.65"] += 1
        elif p < 0.82:
            p_attack_hist["0.65-0.82"] += 1
        else:
            p_attack_hist[">=0.82"] += 1

        if p >= 0.6:
            dl_attack_like += 1

    return c, dl_override, dl_attack_like, p_attack_hist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="jsonl files, e.g. logs/events_fusion.jsonl")
    args = ap.parse_args()

    for f in args.files:
        p = Path(f)
        rows = load_rows(p)
        c, dl_override, dl_attack_like, hist = summarize(rows)
        print(f"\n=== {p} ===")
        print(f"total={len(rows)}")
        print(dict(c))
        print(f"dl_override={dl_override}")
        print(f"dl_attack_like(p_attack>=0.6)={dl_attack_like}")
        print(f"dl_p_attack_hist={hist}")


if __name__ == "__main__":
    main()

